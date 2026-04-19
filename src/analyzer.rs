use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use object::endian::LittleEndian as LE;
use object::read::elf::{FileHeader as ElfFileHeader, ProgramHeader as ElfProgramHeader};
use object::read::macho::MachHeader;
use object::read::pe::{
    ImageNtHeaders, ImageOptionalHeader, ResourceDirectoryEntryData, ResourceNameOrId,
};
use object::read::{File as ObjectFile, Object, ObjectSection, ReadRef};
use object::{FileKind, SectionFlags, pe};

use crate::entropy::{block_entropies, shannon_entropy};
use crate::hash::{hex_encode, md5_hex, sha256_hex};
use crate::model::{
    BinaryFormat, BinaryReport, BinarySummary, CarvedString, FileError, Finding, FormatCount,
    HeaderField, HeaderInfo, ImportAnalysis, ImportEntry, ImportLibrary, PackerHit,
    ProtectionCheck, ResourceInfo, RichHeaderEntryReport, RichHeaderReport, SectionInfo, Severity,
    SummaryReport, SuspiciousImportCombo,
};
use crate::strings::carve_strings;

const ENTROPY_THRESHOLD: f64 = 7.2;
const BLOCK_SIZE: usize = 256;
const SUMMARY_TOP_N: usize = 10;
const MAX_ARCHIVE_DEPTH: usize = 3;
const MAX_ARCHIVE_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES_PER_ARCHIVE: usize = 2048;

#[derive(Debug, Clone, Copy)]
pub struct AnalyzeOptions {
    pub include_yara: bool,
    pub strings_interesting_only: bool,
}

#[derive(Debug)]
struct CandidateBinary {
    logical_path: String,
    file_name: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct SummaryCollector {
    candidates: Vec<CandidateBinary>,
    errors: Vec<FileError>,
    skipped_files: usize,
    archives_scanned: usize,
    archive_entries_scanned: usize,
}

#[derive(Debug)]
struct ArchiveEntry {
    name: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum ArchiveKind {
    Zip,
    Tar,
    Gzip,
}

pub fn analyze_path(path: &Path, options: &AnalyzeOptions) -> Result<BinaryReport> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read binary at {}", path.display()))?;
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    analyze_bytes(&path.display().to_string(), &file_name, &bytes, options)
}

fn analyze_bytes(
    logical_path: &str,
    file_name: &str,
    bytes: &[u8],
    options: &AnalyzeOptions,
) -> Result<BinaryReport> {
    let sha256 = sha256_hex(bytes);
    let file = ObjectFile::parse(&*bytes)?;
    let mut report = match file {
        ObjectFile::Pe32(file) => {
            analyze_pe(logical_path, file_name, bytes, &sha256, &file, options)?
        }
        ObjectFile::Pe64(file) => {
            analyze_pe(logical_path, file_name, bytes, &sha256, &file, options)?
        }
        ObjectFile::Elf32(file) => {
            analyze_elf(logical_path, file_name, bytes, &sha256, &file, options)?
        }
        ObjectFile::Elf64(file) => {
            analyze_elf(logical_path, file_name, bytes, &sha256, &file, options)?
        }
        ObjectFile::MachO32(file) => {
            analyze_macho(logical_path, file_name, bytes, &sha256, &file, options)?
        }
        ObjectFile::MachO64(file) => {
            analyze_macho(logical_path, file_name, bytes, &sha256, &file, options)?
        }
        _ => bail!("unsupported binary format: only PE, ELF, and Mach-O are currently supported"),
    };

    if options.include_yara {
        report.yara_rule = Some(generate_yara_rule(&report));
    }

    Ok(report)
}

pub fn summarize_path(path: &Path, options: &AnalyzeOptions) -> Result<SummaryReport> {
    let mut collector = SummaryCollector::default();
    collect_candidate_inputs(path, &mut collector, 0)?;

    let mut reports = Vec::new();
    let mut by_format = BTreeMap::<&'static str, (BinaryFormat, usize)>::new();

    for candidate in &collector.candidates {
        match analyze_bytes(
            &candidate.logical_path,
            &candidate.file_name,
            &candidate.bytes,
            options,
        ) {
            Ok(report) => {
                let entry = by_format
                    .entry(format_key(report.format))
                    .or_insert((report.format, 0));
                entry.1 += 1;
                reports.push(BinarySummary {
                    path: report.path.clone(),
                    file_name: report.file_name.clone(),
                    format: report.format,
                    risk_score: report.risk_score,
                    findings: report
                        .findings
                        .iter()
                        .take(4)
                        .map(|finding| finding.title.clone())
                        .collect(),
                });
            }
            Err(error) => {
                collector.errors.push(FileError {
                    path: candidate.logical_path.clone(),
                    message: error.to_string(),
                });
            }
        }
    }

    reports.sort_by(|left, right| {
        right
            .risk_score
            .cmp(&left.risk_score)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });

    let highest_risk = reports
        .iter()
        .take(SUMMARY_TOP_N)
        .cloned()
        .collect::<Vec<_>>();
    let analyzed_files = reports.len();
    let scanned_files = collector.candidates.len();

    Ok(SummaryReport {
        root: path.display().to_string(),
        scanned_files,
        analyzed_files,
        skipped_files: collector.skipped_files,
        archives_scanned: collector.archives_scanned,
        archive_entries_scanned: collector.archive_entries_scanned,
        errors: collector.errors,
        by_format: by_format
            .into_values()
            .map(|(format, count)| FormatCount { format, count })
            .collect(),
        highest_risk,
        reports,
    })
}

fn analyze_pe<'data, Pe, R>(
    logical_path: &str,
    file_name: &str,
    bytes: &[u8],
    sha256: &str,
    file: &object::read::pe::PeFile<'data, Pe, R>,
    options: &AnalyzeOptions,
) -> Result<BinaryReport>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let sections = collect_sections(file)?;
    let imports = collect_imports(file)?;
    let import_analysis = build_import_analysis(&imports, true);
    let suspicious_import_combos = suspicious_import_combos(&imports);
    let all_strings = carve_strings(bytes);
    let all_strings_count = all_strings.len();
    let interesting_strings_count = all_strings
        .iter()
        .filter(|item| item.category != "generic")
        .count();
    let carved_strings = filter_strings_for_output(all_strings, options);
    let yara_candidates = select_yara_candidates(&carved_strings);
    let rich_header = collect_rich_header(file);
    let resources = collect_pe_resources(file)?;
    let protections = pe_protections(file);
    let packer_hits = detect_packers(bytes, &sections, BinaryFormat::Pe);
    let findings = collect_findings(
        &sections,
        &suspicious_import_combos,
        &packer_hits,
        &carved_strings,
        &resources,
        &protections,
        rich_header.is_some(),
        &import_analysis,
    );
    let risk_score = compute_risk_score(
        &sections,
        &suspicious_import_combos,
        &packer_hits,
        &carved_strings,
        &resources,
        &protections,
        &import_analysis,
    );

    let nt_headers = file.nt_headers();
    let file_header = nt_headers.file_header();
    let optional_header = nt_headers.optional_header();
    let image_base = optional_header.image_base();
    let entry_point = file.entry();
    let machine = format!("{:?}", file.architecture());

    Ok(BinaryReport {
        path: logical_path.to_string(),
        file_name: file_name.to_string(),
        format: BinaryFormat::Pe,
        size: bytes.len() as u64,
        sha256: sha256.to_string(),
        machine: machine.clone(),
        entry_point,
        image_base: Some(image_base),
        headers: HeaderInfo {
            kind: "pe".to_string(),
            architecture: machine,
            entry_point,
            image_base: Some(image_base),
            details: vec![
                HeaderField {
                    key: "dos_magic".to_string(),
                    value: format!("0x{:x}", file.dos_header().e_magic.get(LE)),
                },
                HeaderField {
                    key: "nt_signature".to_string(),
                    value: format!("0x{:x}", nt_headers.signature()),
                },
                HeaderField {
                    key: "coff_machine".to_string(),
                    value: format!("0x{:x}", file_header.machine.get(LE)),
                },
                HeaderField {
                    key: "number_of_sections".to_string(),
                    value: file_header.number_of_sections.get(LE).to_string(),
                },
                HeaderField {
                    key: "timestamp".to_string(),
                    value: format!("0x{:x}", file_header.time_date_stamp.get(LE)),
                },
                HeaderField {
                    key: "characteristics".to_string(),
                    value: format!("0x{:x}", file_header.characteristics.get(LE)),
                },
                HeaderField {
                    key: "subsystem".to_string(),
                    value: format!("0x{:x}", optional_header.subsystem()),
                },
                HeaderField {
                    key: "dll_characteristics".to_string(),
                    value: format!("0x{:x}", optional_header.dll_characteristics()),
                },
            ],
        },
        sections,
        imports,
        import_analysis,
        suspicious_import_combos,
        carved_strings,
        all_strings_count,
        interesting_strings_count,
        yara_candidates,
        rich_header,
        resources,
        protections,
        packer_hits,
        findings,
        risk_score,
        yara_rule: None,
    })
}

fn analyze_elf<'data, Elf, R>(
    logical_path: &str,
    file_name: &str,
    bytes: &[u8],
    sha256: &str,
    file: &object::read::elf::ElfFile<'data, Elf, R>,
    options: &AnalyzeOptions,
) -> Result<BinaryReport>
where
    Elf: ElfFileHeader,
    R: ReadRef<'data>,
{
    let sections = collect_sections(file)?;
    let imports = collect_imports(file)?;
    let import_analysis = build_import_analysis(&imports, false);
    let suspicious_import_combos = suspicious_import_combos(&imports);
    let all_strings = carve_strings(bytes);
    let all_strings_count = all_strings.len();
    let interesting_strings_count = all_strings
        .iter()
        .filter(|item| item.category != "generic")
        .count();
    let carved_strings = filter_strings_for_output(all_strings, options);
    let yara_candidates = select_yara_candidates(&carved_strings);
    let protections = elf_protections(file)?;
    let packer_hits = detect_packers(bytes, &sections, BinaryFormat::Elf);
    let findings = collect_findings(
        &sections,
        &suspicious_import_combos,
        &packer_hits,
        &carved_strings,
        &[],
        &protections,
        false,
        &import_analysis,
    );
    let risk_score = compute_risk_score(
        &sections,
        &suspicious_import_combos,
        &packer_hits,
        &carved_strings,
        &[],
        &protections,
        &import_analysis,
    );

    let header = file.elf_header();
    let endian = file.endian();
    let machine = format!("{:?}", file.architecture());
    let entry_point = file.entry();
    let build_id = file
        .build_id()?
        .map(hex_encode)
        .unwrap_or_else(|| "none".to_string());

    Ok(BinaryReport {
        path: logical_path.to_string(),
        file_name: file_name.to_string(),
        format: BinaryFormat::Elf,
        size: bytes.len() as u64,
        sha256: sha256.to_string(),
        machine: machine.clone(),
        entry_point,
        image_base: None,
        headers: HeaderInfo {
            kind: "elf".to_string(),
            architecture: machine,
            entry_point,
            image_base: None,
            details: vec![
                HeaderField {
                    key: "class".to_string(),
                    value: format!("0x{:x}", header.e_ident().class),
                },
                HeaderField {
                    key: "endianness".to_string(),
                    value: format!("0x{:x}", header.e_ident().data),
                },
                HeaderField {
                    key: "abi".to_string(),
                    value: format!("0x{:x}", header.e_ident().os_abi),
                },
                HeaderField {
                    key: "elf_type".to_string(),
                    value: format!("0x{:x}", header.e_type(endian)),
                },
                HeaderField {
                    key: "machine".to_string(),
                    value: format!("0x{:x}", header.e_machine(endian)),
                },
                HeaderField {
                    key: "program_headers".to_string(),
                    value: header.e_phnum(endian).to_string(),
                },
                HeaderField {
                    key: "section_headers".to_string(),
                    value: header.e_shnum(endian).to_string(),
                },
                HeaderField {
                    key: "flags".to_string(),
                    value: format!("0x{:x}", header.e_flags(endian)),
                },
                HeaderField {
                    key: "build_id".to_string(),
                    value: build_id,
                },
            ],
        },
        sections,
        imports,
        import_analysis,
        suspicious_import_combos,
        carved_strings,
        all_strings_count,
        interesting_strings_count,
        yara_candidates,
        rich_header: None,
        resources: Vec::new(),
        protections,
        packer_hits,
        findings,
        risk_score,
        yara_rule: None,
    })
}

fn analyze_macho<'data, Mach, R>(
    logical_path: &str,
    file_name: &str,
    bytes: &[u8],
    sha256: &str,
    file: &object::read::macho::MachOFile<'data, Mach, R>,
    options: &AnalyzeOptions,
) -> Result<BinaryReport>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    let sections = collect_sections(file)?;
    let imports = collect_imports(file)?;
    let import_analysis = build_import_analysis(&imports, false);
    let suspicious_import_combos = suspicious_import_combos(&imports);
    let all_strings = carve_strings(bytes);
    let all_strings_count = all_strings.len();
    let interesting_strings_count = all_strings
        .iter()
        .filter(|item| item.category != "generic")
        .count();
    let carved_strings = filter_strings_for_output(all_strings, options);
    let yara_candidates = select_yara_candidates(&carved_strings);
    let protections = macho_protections(file)?;
    let packer_hits = detect_packers(bytes, &sections, BinaryFormat::MachO);
    let findings = collect_findings(
        &sections,
        &suspicious_import_combos,
        &packer_hits,
        &carved_strings,
        &[],
        &protections,
        false,
        &import_analysis,
    );
    let risk_score = compute_risk_score(
        &sections,
        &suspicious_import_combos,
        &packer_hits,
        &carved_strings,
        &[],
        &protections,
        &import_analysis,
    );

    let header = file.macho_header();
    let endian = file.endian();
    let machine = format!("{:?}", file.architecture());
    let entry_point = file.entry();
    let uuid = file
        .mach_uuid()?
        .map(|value| hex_encode(&value))
        .unwrap_or_else(|| "none".to_string());

    Ok(BinaryReport {
        path: logical_path.to_string(),
        file_name: file_name.to_string(),
        format: BinaryFormat::MachO,
        size: bytes.len() as u64,
        sha256: sha256.to_string(),
        machine: machine.clone(),
        entry_point,
        image_base: None,
        headers: HeaderInfo {
            kind: "mach_o".to_string(),
            architecture: machine,
            entry_point,
            image_base: None,
            details: vec![
                HeaderField {
                    key: "magic".to_string(),
                    value: format!("0x{:x}", header.magic()),
                },
                HeaderField {
                    key: "cpu_type".to_string(),
                    value: format!("0x{:x}", header.cputype(endian)),
                },
                HeaderField {
                    key: "cpu_subtype".to_string(),
                    value: format!("0x{:x}", header.cpusubtype(endian)),
                },
                HeaderField {
                    key: "filetype".to_string(),
                    value: format!("0x{:x}", header.filetype(endian)),
                },
                HeaderField {
                    key: "load_commands".to_string(),
                    value: header.ncmds(endian).to_string(),
                },
                HeaderField {
                    key: "flags".to_string(),
                    value: format!("0x{:x}", header.flags(endian)),
                },
                HeaderField {
                    key: "uuid".to_string(),
                    value: uuid,
                },
            ],
        },
        sections,
        imports,
        import_analysis,
        suspicious_import_combos,
        carved_strings,
        all_strings_count,
        interesting_strings_count,
        yara_candidates,
        rich_header: None,
        resources: Vec::new(),
        protections,
        packer_hits,
        findings,
        risk_score,
        yara_rule: None,
    })
}

fn collect_candidate_inputs(
    path: &Path,
    collector: &mut SummaryCollector,
    depth: usize,
) -> Result<()> {
    if path.is_file() {
        match fs::read(path) {
            Ok(bytes) => collect_from_bytes(
                &path.display().to_string(),
                &display_name(path),
                Cow::Owned(bytes),
                collector,
                depth,
            ),
            Err(error) => {
                collector.errors.push(FileError {
                    path: path.display().to_string(),
                    message: format!("failed to read file: {error}"),
                });
            }
        }
        return Ok(());
    }

    if path.is_dir() {
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to read directory {}", path.display()))?
        {
            let entry = entry?;
            let child = entry.path();
            let name = child.file_name().and_then(OsStr::to_str).unwrap_or("");

            if child.is_dir() && matches!(name, ".git" | "target" | "node_modules") {
                continue;
            }

            collect_candidate_inputs(&child, collector, depth)?;
        }
    }

    Ok(())
}

fn collect_from_bytes<'a>(
    logical_path: &str,
    file_name: &str,
    bytes: Cow<'a, [u8]>,
    collector: &mut SummaryCollector,
    depth: usize,
) {
    if is_supported_candidate_bytes(&bytes) {
        collector.candidates.push(CandidateBinary {
            logical_path: logical_path.to_string(),
            file_name: file_name.to_string(),
            bytes: bytes.into_owned(),
        });
        return;
    }

    if depth >= MAX_ARCHIVE_DEPTH {
        collector.skipped_files += 1;
        return;
    }

    match detect_archive_kind(file_name, &bytes) {
        Some(ArchiveKind::Zip) => {
            collector.archives_scanned += 1;
            match extract_zip_entries(&bytes) {
                Ok(entries) => recurse_archive_entries(logical_path, entries, collector, depth + 1),
                Err(error) => collector.errors.push(FileError {
                    path: logical_path.to_string(),
                    message: format!("failed to parse zip archive: {error}"),
                }),
            }
        }
        Some(ArchiveKind::Tar) => {
            collector.archives_scanned += 1;
            match extract_tar_entries(&bytes) {
                Ok(entries) => recurse_archive_entries(logical_path, entries, collector, depth + 1),
                Err(error) => collector.errors.push(FileError {
                    path: logical_path.to_string(),
                    message: format!("failed to parse tar archive: {error}"),
                }),
            }
        }
        Some(ArchiveKind::Gzip) => {
            collector.archives_scanned += 1;
            match extract_gzip_payload(logical_path, file_name, &bytes) {
                Ok((inner_name, payload)) => {
                    let nested_path = format!("{logical_path}!{inner_name}");
                    collect_from_bytes(
                        &nested_path,
                        &inner_name,
                        Cow::Owned(payload),
                        collector,
                        depth + 1,
                    );
                }
                Err(error) => collector.errors.push(FileError {
                    path: logical_path.to_string(),
                    message: format!("failed to decompress gzip archive: {error}"),
                }),
            }
        }
        None => {
            collector.skipped_files += 1;
        }
    }
}

fn recurse_archive_entries(
    logical_path: &str,
    entries: Vec<ArchiveEntry>,
    collector: &mut SummaryCollector,
    depth: usize,
) {
    for entry in entries {
        collector.archive_entries_scanned += 1;
        let nested_path = format!("{logical_path}!{}", entry.name);
        collect_from_bytes(
            &nested_path,
            &display_name(Path::new(&entry.name)),
            Cow::Owned(entry.bytes),
            collector,
            depth,
        );
    }
}

fn is_supported_candidate_bytes(bytes: &[u8]) -> bool {
    matches!(
        FileKind::parse(bytes),
        Ok(FileKind::Pe32)
            | Ok(FileKind::Pe64)
            | Ok(FileKind::Elf32)
            | Ok(FileKind::Elf64)
            | Ok(FileKind::MachO32)
            | Ok(FileKind::MachO64)
    )
}

fn detect_archive_kind(file_name: &str, bytes: &[u8]) -> Option<ArchiveKind> {
    let lower = file_name.to_ascii_lowercase();

    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || lower.ends_with(".zip")
        || lower.ends_with(".jar")
    {
        return Some(ArchiveKind::Zip);
    }

    if is_tar_archive(bytes) || lower.ends_with(".tar") {
        return Some(ArchiveKind::Tar);
    }

    if bytes.starts_with(&[0x1f, 0x8b])
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".gz")
    {
        return Some(ArchiveKind::Gzip);
    }

    None
}

fn is_tar_archive(bytes: &[u8]) -> bool {
    bytes.len() > 262 && &bytes[257..262] == b"ustar"
}

fn extract_zip_entries(bytes: &[u8]) -> Result<Vec<ArchiveEntry>> {
    let eocd = find_zip_eocd(bytes).context("missing end of central directory")?;
    let entry_count = le_u16(bytes, eocd + 10)? as usize;
    let central_dir_offset = le_u32(bytes, eocd + 16)? as usize;
    let mut offset = central_dir_offset;
    let mut entries = Vec::new();

    for _ in 0..entry_count.min(MAX_ARCHIVE_ENTRIES_PER_ARCHIVE) {
        let signature = le_u32(bytes, offset)?;
        if signature != 0x0201_4b50 {
            bail!("invalid central directory entry signature");
        }

        let flags = le_u16(bytes, offset + 8)?;
        let method = le_u16(bytes, offset + 10)?;
        let compressed_size = le_u32(bytes, offset + 20)? as usize;
        let uncompressed_size = le_u32(bytes, offset + 24)? as usize;
        let name_len = le_u16(bytes, offset + 28)? as usize;
        let extra_len = le_u16(bytes, offset + 30)? as usize;
        let comment_len = le_u16(bytes, offset + 32)? as usize;
        let local_header_offset = le_u32(bytes, offset + 42)? as usize;
        let name = string_field(bytes, offset + 46, name_len)?;

        offset = offset
            .checked_add(46 + name_len + extra_len + comment_len)
            .context("zip central directory overflow")?;

        if name.ends_with('/') || flags & 0x0001 != 0 {
            continue;
        }

        if uncompressed_size > MAX_ARCHIVE_ENTRY_BYTES {
            continue;
        }

        let local_sig = le_u32(bytes, local_header_offset)?;
        if local_sig != 0x0403_4b50 {
            bail!("invalid local file header signature");
        }

        let local_name_len = le_u16(bytes, local_header_offset + 26)? as usize;
        let local_extra_len = le_u16(bytes, local_header_offset + 28)? as usize;
        let data_start = local_header_offset
            .checked_add(30 + local_name_len + local_extra_len)
            .context("zip local header overflow")?;
        let data_end = data_start
            .checked_add(compressed_size)
            .context("zip entry overflow")?;
        let compressed = bytes
            .get(data_start..data_end)
            .context("zip entry outside archive bounds")?;

        let data = match method {
            0 => compressed.to_vec(),
            8 => decompress_to_vec_with_limit(compressed, MAX_ARCHIVE_ENTRY_BYTES)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            _ => continue,
        };

        entries.push(ArchiveEntry { name, bytes: data });
    }

    Ok(entries)
}

fn find_zip_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }

    let min_offset = bytes.len().saturating_sub(22 + 65_535);
    (min_offset..=bytes.len() - 4)
        .rev()
        .find(|offset| bytes.get(*offset..*offset + 4) == Some(&b"PK\x05\x06"[..]))
}

fn extract_tar_entries(bytes: &[u8]) -> Result<Vec<ArchiveEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 512 <= bytes.len() && entries.len() < MAX_ARCHIVE_ENTRIES_PER_ARCHIVE {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }

        let name = tar_name(header);
        let size = parse_tar_size(&header[124..136])?;
        let typeflag = header[156];
        let data_start = offset + 512;
        let data_end = data_start.checked_add(size).context("tar entry overflow")?;
        let data = bytes
            .get(data_start..data_end)
            .context("tar entry outside archive bounds")?;

        if matches!(typeflag, 0 | b'0') && !name.is_empty() && size <= MAX_ARCHIVE_ENTRY_BYTES {
            entries.push(ArchiveEntry {
                name,
                bytes: data.to_vec(),
            });
        }

        offset = data_end
            .checked_add((512 - (size % 512)) % 512)
            .context("tar alignment overflow")?;
    }

    Ok(entries)
}

fn tar_name(header: &[u8]) -> String {
    let name = trim_c_string(&header[..100]);
    let prefix = trim_c_string(&header[345..500]);
    if prefix.is_empty() {
        name
    } else if name.is_empty() {
        prefix
    } else {
        format!("{prefix}/{name}")
    }
}

fn parse_tar_size(bytes: &[u8]) -> Result<usize> {
    let trimmed = trim_c_string(bytes).trim().to_string();
    if trimmed.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(trimmed.trim(), 8).context("invalid tar size field")
}

fn extract_gzip_payload(
    logical_path: &str,
    file_name: &str,
    bytes: &[u8],
) -> Result<(String, Vec<u8>)> {
    if bytes.len() < 18 || !bytes.starts_with(&[0x1f, 0x8b]) {
        bail!("invalid gzip header");
    }

    let flags = bytes[3];
    let mut offset = 10usize;
    let mut embedded_name = None;

    if flags & 0x04 != 0 {
        let xlen = le_u16(bytes, offset)? as usize;
        offset = offset
            .checked_add(2 + xlen)
            .context("gzip extra field overflow")?;
    }
    if flags & 0x08 != 0 {
        let end = find_c_string_end(bytes, offset).context("unterminated gzip filename")?;
        embedded_name = Some(String::from_utf8_lossy(&bytes[offset..end]).to_string());
        offset = end + 1;
    }
    if flags & 0x10 != 0 {
        let end = find_c_string_end(bytes, offset).context("unterminated gzip comment")?;
        offset = end + 1;
    }
    if flags & 0x02 != 0 {
        offset = offset.checked_add(2).context("gzip header crc overflow")?;
    }

    let compressed_end = bytes
        .len()
        .checked_sub(8)
        .context("truncated gzip trailer")?;
    let compressed = bytes
        .get(offset..compressed_end)
        .context("gzip payload outside bounds")?;
    let payload = decompress_to_vec_with_limit(compressed, MAX_ARCHIVE_ENTRY_BYTES)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    let inner_name = embedded_name.unwrap_or_else(|| gzip_inner_name(logical_path, file_name));
    Ok((inner_name, payload))
}

fn gzip_inner_name(logical_path: &str, file_name: &str) -> String {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") {
        file_name[..file_name.len() - 3].to_string()
    } else if lower.ends_with(".tgz") {
        format!("{}.tar", &file_name[..file_name.len() - 4])
    } else if lower.ends_with(".gz") {
        file_name[..file_name.len() - 3].to_string()
    } else {
        Path::new(logical_path)
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "decompressed".to_string())
    }
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .context("unexpected end of data while reading u16")?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .context("unexpected end of data while reading u32")?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn string_field(bytes: &[u8], offset: usize, len: usize) -> Result<String> {
    let slice = bytes
        .get(offset..offset + len)
        .context("unexpected end of data while reading string field")?;
    Ok(String::from_utf8_lossy(slice).to_string())
}

fn trim_c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn find_c_string_end(bytes: &[u8], offset: usize) -> Option<usize> {
    bytes
        .get(offset..)?
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| offset + index)
}

fn collect_sections<'data, O>(file: &O) -> Result<Vec<SectionInfo>>
where
    O: Object<'data>,
{
    let mut sections = Vec::new();

    for section in file.sections() {
        let name = section
            .name()
            .map(|value| value.trim_end_matches('\0').to_string())
            .unwrap_or_else(|_| format!("section_{}", section.index().0));
        let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
        let data = section.data().unwrap_or(&[]);
        let entropy = if data.is_empty() {
            0.0
        } else {
            shannon_entropy(data)
        };
        let flags = section_flags(section.flags());
        let suspicious = entropy >= ENTROPY_THRESHOLD || is_exec_and_write(&flags);

        sections.push(SectionInfo {
            name,
            file_offset,
            file_size,
            virtual_address: section.address(),
            virtual_size: section.size(),
            flags,
            entropy,
            block_entropies: block_entropies(data, BLOCK_SIZE),
            suspicious,
        });
    }

    Ok(sections)
}

fn collect_imports<'data, O>(file: &O) -> Result<Vec<ImportEntry>>
where
    O: Object<'data>,
{
    let mut imports = file
        .imports()?
        .into_iter()
        .map(|import| ImportEntry {
            library: String::from_utf8_lossy(import.library()).trim().to_string(),
            symbol: String::from_utf8_lossy(import.name()).trim().to_string(),
        })
        .collect::<Vec<_>>();

    imports.sort_by(|left, right| {
        left.library
            .cmp(&right.library)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    imports.dedup_by(|left, right| left.library == right.library && left.symbol == right.symbol);
    Ok(imports)
}

fn build_import_analysis(imports: &[ImportEntry], calculate_imphash: bool) -> ImportAnalysis {
    let mut by_library = BTreeMap::<String, usize>::new();
    let mut normalized = Vec::new();
    let mut suspicious_libraries = BTreeSet::new();

    for import in imports {
        let library = import.library.to_ascii_lowercase();
        let symbol = import.symbol.to_ascii_lowercase();
        *by_library.entry(library.clone()).or_insert(0) += 1;
        normalized.push(format!("{library}!{symbol}"));

        if is_suspicious_library(&library) {
            suspicious_libraries.insert(library);
        }
    }

    let libraries = by_library
        .into_iter()
        .map(|(name, symbol_count)| ImportLibrary { name, symbol_count })
        .collect::<Vec<_>>();

    let imphash = if calculate_imphash {
        let ordered = imports
            .iter()
            .map(|import| {
                let library = import
                    .library
                    .to_ascii_lowercase()
                    .trim_end_matches(".dll")
                    .to_string();
                let symbol = import.symbol.to_ascii_lowercase();
                format!("{library}.{symbol}")
            })
            .collect::<Vec<_>>()
            .join(",");
        Some(md5_hex(ordered.as_bytes()))
    } else {
        None
    };

    ImportAnalysis {
        imphash,
        fingerprint_sha256: sha256_hex(normalized.join("|").as_bytes()),
        libraries,
        suspicious_libraries: suspicious_libraries.into_iter().collect(),
    }
}

fn collect_rich_header<'data, Pe, R>(
    file: &object::read::pe::PeFile<'data, Pe, R>,
) -> Option<RichHeaderReport>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let rich = file.rich_header_info()?;
    let entries = rich
        .unmasked_entries()
        .map(|entry| {
            let product_id = (entry.comp_id >> 16) as u16;
            let build = (entry.comp_id & 0xffff) as u16;
            let label = rich_product_label(product_id);
            RichHeaderEntryReport {
                product_id,
                build,
                count: entry.count,
                label,
            }
        })
        .collect::<Vec<_>>();

    let mut fingerprint_bytes = Vec::new();
    for entry in &entries {
        fingerprint_bytes.extend_from_slice(&entry.product_id.to_le_bytes());
        fingerprint_bytes.extend_from_slice(&entry.build.to_le_bytes());
        fingerprint_bytes.extend_from_slice(&entry.count.to_le_bytes());
    }

    Some(RichHeaderReport {
        offset: rich.offset,
        length: rich.length,
        xor_key: rich.xor_key,
        fingerprint: sha256_hex(&fingerprint_bytes),
        entries,
    })
}

fn collect_pe_resources<'data, Pe, R>(
    file: &object::read::pe::PeFile<'data, Pe, R>,
) -> Result<Vec<ResourceInfo>>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let Some(directory) = file
        .data_directories()
        .resource_directory(file.data(), &file.section_table())?
    else {
        return Ok(Vec::new());
    };

    let root = directory.root()?;
    let section_table = file.section_table();
    let mut resources = Vec::new();

    for type_entry in root.entries {
        let type_label = resource_name(type_entry.name_or_id(), directory, true)?;
        let Some(name_table) = type_entry.data(directory)?.table() else {
            continue;
        };

        for name_entry in name_table.entries {
            let name_label = resource_name(name_entry.name_or_id(), directory, false)?;
            match name_entry.data(directory)? {
                ResourceDirectoryEntryData::Table(language_table) => {
                    for lang_entry in language_table.entries {
                        let language = lang_entry.name_or_id().id();
                        if let Some(data_entry) = lang_entry.data(directory)?.data() {
                            if let Some(info) = build_resource_info(
                                &section_table,
                                file.data(),
                                &type_label,
                                &name_label,
                                language,
                                data_entry.offset_to_data.get(LE),
                                data_entry.size.get(LE),
                            )? {
                                resources.push(info);
                            }
                        }
                    }
                }
                ResourceDirectoryEntryData::Data(data_entry) => {
                    if let Some(info) = build_resource_info(
                        &section_table,
                        file.data(),
                        &type_label,
                        &name_label,
                        None,
                        data_entry.offset_to_data.get(LE),
                        data_entry.size.get(LE),
                    )? {
                        resources.push(info);
                    }
                }
            }
        }
    }

    resources.sort_by(|left, right| {
        left.resource_type
            .cmp(&right.resource_type)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(resources)
}

fn build_resource_info<'data, R: ReadRef<'data>>(
    section_table: &object::read::pe::SectionTable<'data>,
    data: R,
    resource_type: &str,
    name: &str,
    language: Option<u16>,
    rva: u32,
    size: u32,
) -> Result<Option<ResourceInfo>> {
    let Some(resource_data) = section_table.pe_data_at(data, rva) else {
        return Ok(None);
    };
    let Some(resource_bytes) = resource_data.get(..size as usize) else {
        return Ok(None);
    };

    Ok(Some(ResourceInfo {
        resource_type: resource_type.to_string(),
        name: name.to_string(),
        language,
        size,
        sha256: sha256_hex(resource_bytes),
        summary: resource_summary(resource_type, resource_bytes),
    }))
}

fn resource_name(
    value: ResourceNameOrId,
    directory: object::read::pe::ResourceDirectory<'_>,
    map_type: bool,
) -> Result<String> {
    Ok(match value {
        ResourceNameOrId::Name(name) => name.to_string_lossy(directory)?,
        ResourceNameOrId::Id(id) => {
            if map_type {
                match id {
                    pe::RT_ICON => "icon".to_string(),
                    pe::RT_STRING => "string".to_string(),
                    pe::RT_GROUP_ICON => "group_icon".to_string(),
                    pe::RT_VERSION => "version".to_string(),
                    pe::RT_MANIFEST => "manifest".to_string(),
                    _ => format!("id_{id}"),
                }
            } else {
                format!("id_{id}")
            }
        }
    })
}

fn pe_protections<'data, Pe, R>(
    file: &object::read::pe::PeFile<'data, Pe, R>,
) -> Vec<ProtectionCheck>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    let optional = file.nt_headers().optional_header();
    let flags = optional.dll_characteristics();

    vec![
        ProtectionCheck {
            name: "ASLR".to_string(),
            enabled: Some(flags & pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0),
            detail: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE".to_string(),
        },
        ProtectionCheck {
            name: "HighEntropyVA".to_string(),
            enabled: Some(flags & pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0),
            detail: "64-bit high entropy ASLR".to_string(),
        },
        ProtectionCheck {
            name: "NX".to_string(),
            enabled: Some(flags & pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0),
            detail: "DEP / NX compatibility bit".to_string(),
        },
        ProtectionCheck {
            name: "CFG".to_string(),
            enabled: Some(flags & pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0),
            detail: "Control Flow Guard".to_string(),
        },
        ProtectionCheck {
            name: "NoSEH".to_string(),
            enabled: Some(flags & pe::IMAGE_DLLCHARACTERISTICS_NO_SEH != 0),
            detail: "Structured exception handling disabled".to_string(),
        },
    ]
}

fn elf_protections<'data, Elf, R>(
    file: &object::read::elf::ElfFile<'data, Elf, R>,
) -> Result<Vec<ProtectionCheck>>
where
    Elf: ElfFileHeader,
    R: ReadRef<'data>,
{
    let endian = file.endian();
    let header = file.elf_header();
    let mut gnu_stack = None;
    let mut relro = false;
    let mut interp = None;

    for segment in file.elf_program_headers() {
        match segment.p_type(endian) {
            object::elf::PT_GNU_STACK => {
                gnu_stack = Some(segment.p_flags(endian) & object::elf::PF_X == 0);
            }
            object::elf::PT_GNU_RELRO => {
                relro = true;
            }
            object::elf::PT_INTERP => {
                let start = segment.p_offset(endian).into() as usize;
                let size = segment.p_filesz(endian).into() as usize;
                if let Some(bytes) = file.data().read_bytes_at(start as u64, size as u64).ok() {
                    let value = bytes
                        .iter()
                        .copied()
                        .take_while(|byte| *byte != 0)
                        .collect::<Vec<_>>();
                    interp = Some(String::from_utf8_lossy(&value).to_string());
                }
            }
            _ => {}
        }
    }

    let symbol_count = file.elf_symbol_table().len();
    let is_pie = header.e_type(endian) == object::elf::ET_DYN && interp.is_some();
    let needed = file
        .imports()?
        .into_iter()
        .map(|item| String::from_utf8_lossy(item.library()).to_string())
        .filter(|item| !item.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    Ok(vec![
        ProtectionCheck {
            name: "PIE".to_string(),
            enabled: Some(is_pie),
            detail: format!("ELF type 0x{:x}", header.e_type(endian)),
        },
        ProtectionCheck {
            name: "NX".to_string(),
            enabled: gnu_stack,
            detail: "PT_GNU_STACK executable bit".to_string(),
        },
        ProtectionCheck {
            name: "RELRO".to_string(),
            enabled: Some(relro),
            detail: "PT_GNU_RELRO presence".to_string(),
        },
        ProtectionCheck {
            name: "Stripped".to_string(),
            enabled: Some(symbol_count <= 1),
            detail: format!("{symbol_count} symbols in SHT_SYMTAB"),
        },
        ProtectionCheck {
            name: "Interpreter".to_string(),
            enabled: interp.as_ref().map(|_| true),
            detail: interp.unwrap_or_else(|| "none".to_string()),
        },
        ProtectionCheck {
            name: "DT_NEEDED".to_string(),
            enabled: Some(!needed.is_empty()),
            detail: if needed.is_empty() {
                "none".to_string()
            } else {
                needed.join(", ")
            },
        },
    ])
}

fn macho_protections<'data, Mach, R>(
    file: &object::read::macho::MachOFile<'data, Mach, R>,
) -> Result<Vec<ProtectionCheck>>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    let header = file.macho_header();
    let endian = file.endian();
    let flags = header.flags(endian);
    let uuid = file
        .mach_uuid()?
        .map(|value| hex_encode(&value))
        .unwrap_or_else(|| "none".to_string());

    Ok(vec![
        ProtectionCheck {
            name: "PIE".to_string(),
            enabled: Some(flags & object::macho::MH_PIE != 0),
            detail: "MH_PIE".to_string(),
        },
        ProtectionCheck {
            name: "HeapNX".to_string(),
            enabled: Some(flags & object::macho::MH_NO_HEAP_EXECUTION != 0),
            detail: "MH_NO_HEAP_EXECUTION".to_string(),
        },
        ProtectionCheck {
            name: "ExecStack".to_string(),
            enabled: Some(flags & object::macho::MH_ALLOW_STACK_EXECUTION != 0),
            detail: "MH_ALLOW_STACK_EXECUTION".to_string(),
        },
        ProtectionCheck {
            name: "UUID".to_string(),
            enabled: Some(uuid != "none"),
            detail: uuid,
        },
    ])
}

fn section_flags(flags: SectionFlags) -> Vec<String> {
    match flags {
        SectionFlags::Elf { sh_flags } => {
            let mut out = Vec::new();
            if sh_flags & (object::elf::SHF_EXECINSTR as u64) != 0 {
                out.push("execute".to_string());
            }
            if sh_flags & (object::elf::SHF_WRITE as u64) != 0 {
                out.push("write".to_string());
            }
            out.push("read".to_string());
            out
        }
        SectionFlags::MachO { flags } => {
            let mut out = vec!["read".to_string()];
            if flags & object::macho::S_ATTR_PURE_INSTRUCTIONS != 0
                || flags & object::macho::S_ATTR_SOME_INSTRUCTIONS != 0
            {
                out.push("execute".to_string());
            }
            if flags & object::macho::S_ZEROFILL == 0 {
                out.push("mapped".to_string());
            }
            out
        }
        SectionFlags::Coff { characteristics } => pe_section_flags(characteristics),
        _ => Vec::new(),
    }
}

fn pe_section_flags(characteristics: u32) -> Vec<String> {
    let mut flags = Vec::new();
    if characteristics & 0x2000_0000 != 0 {
        flags.push("execute".to_string());
    }
    if characteristics & 0x4000_0000 != 0 {
        flags.push("read".to_string());
    }
    if characteristics & 0x8000_0000 != 0 {
        flags.push("write".to_string());
    }
    if characteristics & 0x20 != 0 {
        flags.push("code".to_string());
    }
    if characteristics & 0x40 != 0 {
        flags.push("initialized_data".to_string());
    }
    flags
}

fn filter_strings_for_output(
    strings: Vec<CarvedString>,
    options: &AnalyzeOptions,
) -> Vec<CarvedString> {
    let mut output = if options.strings_interesting_only {
        strings
            .into_iter()
            .filter(|item| item.category != "generic")
            .collect::<Vec<_>>()
    } else {
        strings
    };
    output.truncate(200);
    output
}

fn suspicious_import_combos(imports: &[ImportEntry]) -> Vec<SuspiciousImportCombo> {
    let known = imports
        .iter()
        .map(|item| {
            format!(
                "{}!{}",
                item.library.to_ascii_lowercase(),
                item.symbol.to_ascii_lowercase()
            )
        })
        .collect::<HashSet<_>>();
    let flat_symbols = imports
        .iter()
        .map(|item| item.symbol.to_ascii_lowercase())
        .collect::<HashSet<_>>();

    let combos = [
        (
            "injector",
            Severity::Critical,
            vec![
                "kernel32.dll!virtualalloc",
                "kernel32.dll!writeprocessmemory",
                "kernel32.dll!createremotethread",
            ],
            "Classic remote-thread injection chain",
        ),
        (
            "shellcode_loader",
            Severity::High,
            vec![
                "kernel32.dll!virtualalloc",
                "kernel32.dll!virtualprotect",
                "kernel32.dll!createthread",
            ],
            "RWX allocation and thread start sequence",
        ),
        (
            "process_hollowing",
            Severity::Critical,
            vec![
                "ntdll.dll!ntunmapviewofsection",
                "kernel32.dll!writeprocessmemory",
                "kernel32.dll!setthreadcontext",
                "kernel32.dll!resumethread",
            ],
            "Process hollowing related API set",
        ),
        (
            "credential_dumping",
            Severity::High,
            vec!["kernel32.dll!openprocess", "dbghelp.dll!minidumpwritedump"],
            "Possible LSASS access and dump workflow",
        ),
        (
            "dynamic_resolution",
            Severity::Medium,
            vec!["kernel32.dll!loadlibrarya", "kernel32.dll!getprocaddress"],
            "Runtime API resolution often used for evasion",
        ),
    ];

    let mut out = Vec::new();
    for (name, severity, apis, rationale) in combos {
        let matched = apis
            .iter()
            .filter(|api| {
                let symbol = api.split('!').nth(1).unwrap_or_default();
                known.contains(**api) || flat_symbols.iter().any(|candidate| candidate == symbol)
            })
            .map(|api| (*api).to_string())
            .collect::<Vec<_>>();

        if matched.len() == apis.len() {
            out.push(SuspiciousImportCombo {
                name: name.to_string(),
                severity,
                matched,
                rationale: rationale.to_string(),
            });
        }
    }

    out
}

fn detect_packers(bytes: &[u8], sections: &[SectionInfo], format: BinaryFormat) -> Vec<PackerHit> {
    let mut hits = Vec::new();
    for (marker, name, description) in [
        (b"UPX!".as_slice(), "UPX", "UPX marker found in file image"),
        (b"UPX0".as_slice(), "UPX", "UPX section marker found"),
        (b"UPX1".as_slice(), "UPX", "UPX section marker found"),
        (
            b"MPRESS1".as_slice(),
            "MPRESS",
            "MPRESS section marker found",
        ),
        (
            b"MPRESS2".as_slice(),
            "MPRESS",
            "MPRESS section marker found",
        ),
        (b"Themida".as_slice(), "Themida", "Themida signature found"),
        (b"Petite".as_slice(), "Petite", "Petite marker found"),
        (b"ASPack".as_slice(), "ASPack", "ASPack marker found"),
        (
            b"kkrunchy".as_slice(),
            "kkrunchy",
            "kkrunchy packer string found",
        ),
        (b"PEC2".as_slice(), "PECompact", "PECompact marker found"),
    ] {
        for offset in find_all(bytes, marker) {
            hits.push(PackerHit {
                name: name.to_string(),
                offset: offset as u64,
                description: description.to_string(),
            });
        }
    }

    let suspicious_names = match format {
        BinaryFormat::Pe => &[
            "upx0", "upx1", "upx2", ".aspack", ".adata", ".packed", ".petite", ".boom",
        ][..],
        BinaryFormat::Elf => &["upx0", "upx1", "upx2", ".packed"][..],
        BinaryFormat::MachO => &["__upx", "__packed"][..],
    };

    for section in sections {
        let lower = section.name.to_ascii_lowercase();
        if suspicious_names.contains(&lower.as_str()) {
            hits.push(PackerHit {
                name: "SectionName".to_string(),
                offset: section.file_offset,
                description: format!("packer-like section name: {}", section.name),
            });
        }
    }

    hits.sort_by_key(|hit| hit.offset);
    hits.dedup_by(|left, right| left.name == right.name && left.offset == right.offset);
    hits
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for idx in 0..=(haystack.len() - needle.len()) {
        if &haystack[idx..idx + needle.len()] == needle {
            out.push(idx);
        }
    }
    out
}

fn collect_findings(
    sections: &[SectionInfo],
    suspicious_import_combos: &[SuspiciousImportCombo],
    packer_hits: &[PackerHit],
    carved_strings: &[CarvedString],
    resources: &[ResourceInfo],
    protections: &[ProtectionCheck],
    has_rich_header: bool,
    import_analysis: &ImportAnalysis,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(entropy_findings(sections));
    findings.extend(combo_findings(suspicious_import_combos));
    findings.extend(packer_findings(packer_hits));
    findings.extend(string_findings(carved_strings));
    findings.extend(resource_findings(resources));
    findings.extend(protection_findings(protections));
    findings.extend(import_findings(import_analysis));
    if has_rich_header {
        findings.push(Finding {
            severity: Severity::Low,
            title: "PE Rich header present".to_string(),
            detail: "Compiler/toolchain fingerprint data is available".to_string(),
        });
    }
    findings
}

fn entropy_findings(sections: &[SectionInfo]) -> Vec<Finding> {
    sections
        .iter()
        .filter(|section| section.entropy >= ENTROPY_THRESHOLD)
        .map(|section| Finding {
            severity: if section.entropy >= 7.7 {
                Severity::High
            } else {
                Severity::Medium
            },
            title: format!("High-entropy section {}", section.name),
            detail: format!(
                "Entropy {:.2} suggests compression, encryption, or packed payloads",
                section.entropy
            ),
        })
        .collect()
}

fn combo_findings(combos: &[SuspiciousImportCombo]) -> Vec<Finding> {
    combos
        .iter()
        .map(|combo| Finding {
            severity: combo.severity,
            title: format!("Suspicious API combo: {}", combo.name),
            detail: combo.rationale.clone(),
        })
        .collect()
}

fn packer_findings(hits: &[PackerHit]) -> Vec<Finding> {
    hits.iter()
        .map(|hit| Finding {
            severity: Severity::High,
            title: format!("Packer signature: {}", hit.name),
            detail: hit.description.clone(),
        })
        .collect()
}

fn string_findings(strings: &[CarvedString]) -> Vec<Finding> {
    let categories = strings
        .iter()
        .filter(|item| item.category != "generic")
        .map(|item| item.category.clone())
        .collect::<BTreeSet<_>>();

    categories
        .into_iter()
        .map(|category| Finding {
            severity: match category.as_str() {
                "winapi" | "url" | "ipv4" => Severity::Medium,
                "registry" | "crypto" => Severity::Low,
                _ => Severity::Low,
            },
            title: format!("Interesting strings: {category}"),
            detail: format!("Recovered at least one {category} indicator from the file image"),
        })
        .collect()
}

fn resource_findings(resources: &[ResourceInfo]) -> Vec<Finding> {
    resources
        .iter()
        .filter(|resource| {
            resource.summary.contains("embedded PE")
                || resource.summary.contains("embedded ELF")
                || resource.resource_type == "manifest"
        })
        .map(|resource| Finding {
            severity: if resource.summary.contains("embedded") {
                Severity::High
            } else {
                Severity::Low
            },
            title: format!("Resource {}", resource.resource_type),
            detail: resource.summary.clone(),
        })
        .collect()
}

fn protection_findings(protections: &[ProtectionCheck]) -> Vec<Finding> {
    protections
        .iter()
        .filter_map(|item| match item.enabled {
            Some(false)
                if matches!(item.name.as_str(), "ASLR" | "NX" | "CFG" | "PIE" | "RELRO") =>
            {
                Some(Finding {
                    severity: Severity::Medium,
                    title: format!("Protection disabled: {}", item.name),
                    detail: item.detail.clone(),
                })
            }
            Some(true) if item.name == "ExecStack" => Some(Finding {
                severity: Severity::Medium,
                title: "Executable stack allowed".to_string(),
                detail: item.detail.clone(),
            }),
            Some(true) if item.name == "Stripped" => Some(Finding {
                severity: Severity::Low,
                title: "Binary stripped".to_string(),
                detail: item.detail.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn import_findings(import_analysis: &ImportAnalysis) -> Vec<Finding> {
    if import_analysis.suspicious_libraries.is_empty() {
        Vec::new()
    } else {
        vec![Finding {
            severity: Severity::Medium,
            title: "Suspicious import libraries".to_string(),
            detail: import_analysis.suspicious_libraries.join(", "),
        }]
    }
}

fn compute_risk_score(
    sections: &[SectionInfo],
    combos: &[SuspiciousImportCombo],
    packers: &[PackerHit],
    strings: &[CarvedString],
    resources: &[ResourceInfo],
    protections: &[ProtectionCheck],
    import_analysis: &ImportAnalysis,
) -> u8 {
    let mut score = 0u32;

    let high_entropy_count = sections
        .iter()
        .filter(|section| section.entropy >= ENTROPY_THRESHOLD)
        .count() as u32;
    score += (high_entropy_count * 10).min(30);

    if sections
        .iter()
        .any(|section| is_exec_and_write(&section.flags))
    {
        score += 15;
    }

    for combo in combos {
        score += match combo.severity {
            Severity::Critical => 25,
            Severity::High => 18,
            Severity::Medium => 12,
            Severity::Low => 5,
        };
    }

    score += (packers.len() as u32 * 15).min(30);

    let interesting_strings = strings
        .iter()
        .filter(|item| {
            matches!(
                item.category.as_str(),
                "url" | "ipv4" | "registry" | "winapi" | "crypto"
            )
        })
        .count() as u32;
    score += interesting_strings.min(10);

    if !resources.is_empty() {
        score += 5;
    }
    if !import_analysis.suspicious_libraries.is_empty() {
        score += 8;
    }

    for protection in protections {
        match protection.name.as_str() {
            "ASLR" | "NX" | "CFG" | "PIE" | "RELRO" if protection.enabled == Some(false) => {
                score += 8
            }
            "ExecStack" if protection.enabled == Some(true) => score += 6,
            _ => {}
        }
    }

    score.min(100) as u8
}

fn is_exec_and_write(flags: &[String]) -> bool {
    flags.iter().any(|flag| flag == "execute") && flags.iter().any(|flag| flag == "write")
}

fn select_yara_candidates(strings: &[CarvedString]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut scored = strings
        .iter()
        .filter(|item| item.category != "generic")
        .filter_map(|item| {
            let trimmed = item.value.trim();
            if trimmed.len() < 6 || trimmed.len() > 96 || is_noisy_string(trimmed) {
                return None;
            }
            let key = trimmed.to_ascii_lowercase();
            if !seen.insert(key) {
                return None;
            }
            let score = yara_candidate_score(item);
            Some((score, trimmed.to_string()))
        })
        .collect::<Vec<_>>();

    scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    scored.into_iter().take(8).map(|(_, value)| value).collect()
}

fn yara_candidate_score(item: &CarvedString) -> i32 {
    let category_score = match item.category.as_str() {
        "url" => 100,
        "registry" => 85,
        "filesystem" => 75,
        "winapi" => 70,
        "crypto" => 60,
        "ipv4" => 55,
        _ => 10,
    };
    category_score + item.value.len().min(40) as i32
}

fn is_noisy_string(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "this program cannot be run in dos mode",
        "microsoft",
        "copyright",
        "kernel32.dll",
        "msvcrt",
        "libsystem",
        ".text",
        ".data",
        ".rdata",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn generate_yara_rule(report: &BinaryReport) -> String {
    let rule_name = sanitise_rule_name(&report.file_name);
    let strings = report
        .yara_candidates
        .iter()
        .take(6)
        .enumerate()
        .map(|(idx, value)| format!("        $s{idx} = \"{}\" ascii wide", yara_escape(value)))
        .collect::<Vec<_>>();

    let mut imports = Vec::new();
    if matches!(report.format, BinaryFormat::Pe) {
        imports.push("import \"pe\"".to_string());
    }
    imports.push("import \"math\"".to_string());

    let base_condition = match report.format {
        BinaryFormat::Pe => "uint16(0) == 0x5A4D".to_string(),
        BinaryFormat::Elf => "uint32(0) == 0x464C457F".to_string(),
        BinaryFormat::MachO => {
            "(uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe)".to_string()
        }
    };

    let string_condition = if strings.is_empty() {
        "true".to_string()
    } else if strings.len() == 1 {
        "$s0".to_string()
    } else {
        "2 of ($s*)".to_string()
    };

    let entropy_condition =
        "for any i in (0..(filesize / 256)) : (math.entropy(i * 256, 256) > 7.2)";
    let imports_preview = report
        .imports
        .iter()
        .take(10)
        .map(|item| format!("{}!{}", item.library, item.symbol))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "{imports}\n\nrule binscope_{rule_name} {{\n    meta:\n        author = \"binscope\"\n        generated = \"true\"\n        file_name = \"{file_name}\"\n        sha256 = \"{sha256}\"\n        import_fingerprint = \"{import_fingerprint}\"\n        imports_preview = \"{imports_preview}\"\n    strings:\n{strings_block}\n    condition:\n        {base_condition} and\n        {string_condition} and\n        {entropy_condition}\n}}",
        imports = imports.join("\n"),
        rule_name = rule_name,
        file_name = yara_escape(&report.file_name),
        sha256 = report.sha256,
        import_fingerprint = report
            .import_analysis
            .imphash
            .as_deref()
            .unwrap_or(&report.import_analysis.fingerprint_sha256),
        imports_preview = yara_escape(&imports_preview),
        strings_block = if strings.is_empty() {
            "        // add environment-specific strings here".to_string()
        } else {
            strings.join("\n")
        },
        base_condition = base_condition,
        string_condition = string_condition,
        entropy_condition = entropy_condition
    )
}

fn sanitise_rule_name(file_name: &str) -> String {
    let mut out = String::new();
    for ch in file_name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn yara_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('\n', "\\n")
}

fn rich_product_label(product_id: u16) -> String {
    match product_id {
        0 => "unknown".to_string(),
        1 => "import".to_string(),
        2 => "linker510".to_string(),
        3 => "cvtomf510".to_string(),
        4 => "linker600".to_string(),
        7 => "linker700".to_string(),
        14 => "masm700".to_string(),
        29 => "cvtres700".to_string(),
        42 => "utc13_cpp".to_string(),
        43 => "utc13_c".to_string(),
        44 => "utc12_basic".to_string(),
        61 => "utc14_cpp".to_string(),
        62 => "utc14_c".to_string(),
        77 => "utc15_cpp".to_string(),
        78 => "utc15_c".to_string(),
        93 => "utc16_cpp".to_string(),
        94 => "utc16_c".to_string(),
        _ => format!("product_{product_id}"),
    }
}

fn resource_summary(resource_type: &str, bytes: &[u8]) -> String {
    if bytes.starts_with(b"MZ") {
        return "embedded PE payload".to_string();
    }
    if bytes.starts_with(b"\x7fELF") {
        return "embedded ELF payload".to_string();
    }

    match resource_type {
        "manifest" => {
            let text = String::from_utf8_lossy(bytes);
            if text.contains("<assembly") {
                "XML application manifest".to_string()
            } else {
                "manifest resource".to_string()
            }
        }
        "version" => "version information".to_string(),
        "icon" | "group_icon" => "icon resource".to_string(),
        "string" => "string table resource".to_string(),
        _ => format!("resource blob ({})", bytes.len()),
    }
}

fn is_suspicious_library(library: &str) -> bool {
    matches!(
        library,
        "kernel32.dll"
            | "ntdll.dll"
            | "advapi32.dll"
            | "dbghelp.dll"
            | "wininet.dll"
            | "ws2_32.dll"
            | "urlmon.dll"
            | "crypt32.dll"
            | "bcrypt.dll"
    )
}

fn format_key(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Pe => "pe",
        BinaryFormat::Elf => "elf",
        BinaryFormat::MachO => "macho",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_import_analysis, detect_packers, find_all, generate_yara_rule,
        select_yara_candidates, suspicious_import_combos,
    };
    use crate::model::{
        BinaryFormat, BinaryReport, CarvedString, HeaderInfo, ImportAnalysis, ImportEntry,
        ProtectionCheck, SectionInfo, StringEncoding,
    };

    #[test]
    fn finds_packer_markers() {
        let hits = detect_packers(b"AAAAUPX!BBBBMPRESS1", &[], BinaryFormat::Pe);
        assert!(hits.iter().any(|hit| hit.name == "UPX"));
        assert!(hits.iter().any(|hit| hit.name == "MPRESS"));
    }

    #[test]
    fn detects_suspicious_import_sets() {
        let imports = vec![
            ImportEntry {
                library: "kernel32.dll".to_string(),
                symbol: "VirtualAlloc".to_string(),
            },
            ImportEntry {
                library: "kernel32.dll".to_string(),
                symbol: "WriteProcessMemory".to_string(),
            },
            ImportEntry {
                library: "kernel32.dll".to_string(),
                symbol: "CreateRemoteThread".to_string(),
            },
        ];
        let combos = suspicious_import_combos(&imports);
        assert!(combos.iter().any(|combo| combo.name == "injector"));
    }

    #[test]
    fn builds_imphash() {
        let imports = vec![
            ImportEntry {
                library: "KERNEL32.dll".to_string(),
                symbol: "VirtualAlloc".to_string(),
            },
            ImportEntry {
                library: "USER32.dll".to_string(),
                symbol: "MessageBoxA".to_string(),
            },
        ];
        let analysis = build_import_analysis(&imports, true);
        assert!(analysis.imphash.is_some());
        assert_eq!(analysis.libraries.len(), 2);
    }

    #[test]
    fn prefers_specific_yara_candidates() {
        let strings = vec![
            CarvedString {
                offset: 0,
                value: "http://example.com/payload".to_string(),
                encoding: StringEncoding::Ascii,
                category: "url".to_string(),
            },
            CarvedString {
                offset: 10,
                value: "kernel32.dll".to_string(),
                encoding: StringEncoding::Ascii,
                category: "generic".to_string(),
            },
        ];
        let candidates = select_yara_candidates(&strings);
        assert_eq!(candidates, vec!["http://example.com/payload".to_string()]);
    }

    #[test]
    fn generates_yara_rule_safely() {
        let report = BinaryReport {
            path: "sample.exe".to_string(),
            file_name: "sample.exe".to_string(),
            format: BinaryFormat::Pe,
            size: 1024,
            sha256: "abcd".to_string(),
            machine: "I386".to_string(),
            entry_point: 0x401000,
            image_base: Some(0x400000),
            headers: HeaderInfo {
                kind: "pe".to_string(),
                architecture: "I386".to_string(),
                entry_point: 0x401000,
                image_base: Some(0x400000),
                details: Vec::new(),
            },
            sections: vec![SectionInfo {
                name: ".text".to_string(),
                file_offset: 0,
                file_size: 100,
                virtual_address: 0x1000,
                virtual_size: 100,
                flags: vec!["execute".to_string(), "read".to_string()],
                entropy: 7.5,
                block_entropies: vec![7.5],
                suspicious: true,
            }],
            imports: vec![ImportEntry {
                library: "kernel32.dll".to_string(),
                symbol: "VirtualAlloc".to_string(),
            }],
            import_analysis: ImportAnalysis {
                imphash: Some("deadbeef".to_string()),
                fingerprint_sha256: "feedface".to_string(),
                libraries: Vec::new(),
                suspicious_libraries: vec!["kernel32.dll".to_string()],
            },
            suspicious_import_combos: Vec::new(),
            carved_strings: vec![CarvedString {
                offset: 0x100,
                value: "http://example.com".to_string(),
                encoding: StringEncoding::Ascii,
                category: "url".to_string(),
            }],
            all_strings_count: 1,
            interesting_strings_count: 1,
            yara_candidates: vec!["http://example.com".to_string()],
            rich_header: None,
            resources: Vec::new(),
            protections: vec![ProtectionCheck {
                name: "NX".to_string(),
                enabled: Some(true),
                detail: "DEP".to_string(),
            }],
            packer_hits: Vec::new(),
            findings: Vec::new(),
            risk_score: 80,
            yara_rule: None,
        };

        let rule = generate_yara_rule(&report);
        assert!(rule.contains("binscope_sample_exe"));
        assert!(rule.contains("http://example.com"));
        assert!(rule.contains("deadbeef"));
    }

    #[test]
    fn finds_all_matches() {
        assert_eq!(find_all(b"ABABA", b"ABA"), vec![0, 2]);
    }
}
