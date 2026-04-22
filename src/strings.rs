use std::sync::OnceLock;

use regex::Regex;

use crate::model::{CarvedString, StringEncoding};

const MIN_LEN: usize = 5;
const MAX_STRINGS: usize = 2_000;

pub fn carve_strings(bytes: &[u8]) -> Vec<CarvedString> {
    let mut out = Vec::new();
    out.extend(carve_ascii(bytes));
    out.extend(carve_utf16le(bytes));
    out.sort_by_key(|item| item.offset);
    out.truncate(MAX_STRINGS);
    out
}

fn carve_ascii(bytes: &[u8]) -> Vec<CarvedString> {
    let mut out = Vec::new();
    let mut start = None;

    for (idx, byte) in bytes.iter().enumerate() {
        if is_ascii_visible(*byte) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(begin) = start.take() {
            if idx - begin >= MIN_LEN {
                let value = String::from_utf8_lossy(&bytes[begin..idx]).to_string();
                out.push(CarvedString {
                    offset: begin as u64,
                    category: categorise_string(&value),
                    value,
                    encoding: StringEncoding::Ascii,
                });
            }
        }
    }

    if let Some(begin) = start {
        if bytes.len() - begin >= MIN_LEN {
            let value = String::from_utf8_lossy(&bytes[begin..]).to_string();
            out.push(CarvedString {
                offset: begin as u64,
                category: categorise_string(&value),
                value,
                encoding: StringEncoding::Ascii,
            });
        }
    }

    out
}

fn carve_utf16le(bytes: &[u8]) -> Vec<CarvedString> {
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx + (MIN_LEN * 2) <= bytes.len() {
        if is_ascii_visible(bytes[idx]) && bytes[idx + 1] == 0 {
            let start = idx;
            let mut utf16 = Vec::new();

            while idx + 1 < bytes.len() && is_ascii_visible(bytes[idx]) && bytes[idx + 1] == 0 {
                utf16.push(bytes[idx] as u16);
                idx += 2;
            }

            if utf16.len() >= MIN_LEN {
                if let Ok(value) = String::from_utf16(&utf16) {
                    out.push(CarvedString {
                        offset: start as u64,
                        category: categorise_string(&value),
                        value,
                        encoding: StringEncoding::Utf16Le,
                    });
                }
            }
        } else {
            idx += 1;
        }
    }

    out
}

fn is_ascii_visible(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t')
}

fn categorise_string(value: &str) -> String {
    let value_lower = value.to_ascii_lowercase();
    if url_re().is_match(value) {
        "url".to_string()
    } else if ipv4_re().is_match(value) {
        "ipv4".to_string()
    } else if registry_re().is_match(value) {
        "registry".to_string()
    } else if windows_path_re().is_match(value) || unix_path_re().is_match(value) {
        "filesystem".to_string()
    } else if is_suspicious_api(&value_lower) {
        "winapi".to_string()
    } else if contains_crypto_term(&value_lower) {
        "crypto".to_string()
    } else {
        "generic".to_string()
    }
}

fn is_suspicious_api(value_lower: &str) -> bool {
    [
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "ntunmapviewofsection",
        "setthreadcontext",
        "resumethread",
        "winexec",
        "shellexecute",
        "loadlibrary",
        "getprocaddress",
    ]
    .iter()
    .any(|needle| value_lower.contains(needle))
}

fn contains_crypto_term(value_lower: &str) -> bool {
    [
        "aes",
        "rc4",
        "rsa",
        "chacha",
        "xor",
        "salsa20",
        "curve25519",
    ]
    .iter()
    .any(|needle| value_lower.contains(needle))
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s"']+"#).expect("valid URL regex"))
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        )
        .expect("valid IP regex")
    })
}

fn registry_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:hkey_local_machine|hklm|hkey_current_user|hkcu|hkey_classes_root|hkcr|hkey_users|hku)\\[^\r\n\t]+",
        )
        .expect("valid registry regex")
    })
}

fn windows_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b[a-z]:\\[^\r\n\t]+").expect("valid path regex"))
}

fn unix_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?-u)(?:^|[\s"'])(/[A-Za-z0-9._/\-]{4,})"#).expect("valid path regex")
    })
}

#[cfg(test)]
mod tests {
    use super::carve_strings;

    #[test]
    fn carves_ascii_and_utf16() {
        let mut bytes = b"hello http://example.com".to_vec();
        bytes.extend_from_slice(&[0, 1, 2, 3]);
        bytes.extend_from_slice(&[b'W', 0, b'i', 0, b'n', 0, b'E', 0, b'x', 0, b'e', 0]);
        let strings = carve_strings(&bytes);
        assert!(
            strings
                .iter()
                .any(|item| item.value == "hello http://example.com")
        );
        assert!(strings.iter().any(|item| item.value == "WinExe"));
    }

    #[test]
    fn categorises_registry_and_api() {
        let bytes = b"HKCU\\Software\\Microsoft\x00WriteProcessMemory\x00".to_vec();
        let strings = carve_strings(&bytes);
        assert!(strings.iter().any(|item| item.category == "registry"));
        assert!(strings.iter().any(|item| item.category == "winapi"));
    }

    #[test]
    fn categorises_filesystem_and_crypto_strings() {
        let bytes = b"/tmp/payload.bin\x00curve25519 session key\x00".to_vec();
        let strings = carve_strings(&bytes);
        assert!(strings.iter().any(|item| item.category == "filesystem"));
        assert!(strings.iter().any(|item| item.category == "crypto"));
    }

    #[test]
    fn truncates_total_strings_to_guard_memory() {
        let mut bytes = Vec::new();
        for idx in 0..2_200 {
            bytes.extend_from_slice(format!("value-{idx:04}\x00").as_bytes());
        }

        let strings = carve_strings(&bytes);
        assert_eq!(strings.len(), 2_000);
    }
}
