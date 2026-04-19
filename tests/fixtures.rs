use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use binscope::PublicAnalyzeOptions as AnalyzeOptions;
use binscope::{BinaryFormat, public_analyze_path, public_summarize_path};
use miniz_oxide::deflate::compress_to_vec;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("fixtures")
        .join(name)
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("binscope-{label}-{unique}"));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
fn analyzes_elf_fixture() {
    let report = public_analyze_path(
        &fixture("sample_elf"),
        &AnalyzeOptions {
            include_yara: true,
            strings_interesting_only: true,
        },
    )
    .expect("analyze elf fixture");

    assert_eq!(report.format, BinaryFormat::Elf);
    assert!(!report.sections.is_empty());
    assert!(report.yara_rule.is_some());
}

#[test]
fn analyzes_pe_fixture() {
    let report = public_analyze_path(
        &fixture("sample_pe.exe"),
        &AnalyzeOptions {
            include_yara: false,
            strings_interesting_only: false,
        },
    )
    .expect("analyze pe fixture");

    assert_eq!(report.format, BinaryFormat::Pe);
    assert!(report.import_analysis.imphash.is_some());
}

#[test]
fn analyzes_macho_fixture() {
    let report = public_analyze_path(
        &fixture("sample_macho"),
        &AnalyzeOptions {
            include_yara: false,
            strings_interesting_only: true,
        },
    )
    .expect("analyze macho fixture");

    assert_eq!(report.format, BinaryFormat::MachO);
    assert!(report.protections.iter().any(|check| check.name == "PIE"));
}

#[test]
fn summarizes_fixture_directory() {
    let summary = public_summarize_path(
        &fixture(""),
        &AnalyzeOptions {
            include_yara: false,
            strings_interesting_only: true,
        },
    )
    .expect("summarize fixtures");

    assert!(summary.analyzed_files >= 3);
    assert!(
        summary
            .by_format
            .iter()
            .any(|item| item.format == BinaryFormat::Elf)
    );
    assert!(
        summary
            .by_format
            .iter()
            .any(|item| item.format == BinaryFormat::Pe)
    );
    assert!(
        summary
            .by_format
            .iter()
            .any(|item| item.format == BinaryFormat::MachO)
    );
    assert_eq!(summary.archives_scanned, 0);
}

#[test]
fn summarizes_zip_archive_contents() {
    let root = temp_dir("zip");
    let zip_path = root.join("bundle.zip");
    let elf_bytes = fs::read(fixture("sample_elf")).expect("read elf fixture");
    fs::write(&zip_path, make_zip_archive("nested/sample_elf", &elf_bytes)).expect("write zip");

    let summary = public_summarize_path(
        &root,
        &AnalyzeOptions {
            include_yara: false,
            strings_interesting_only: true,
        },
    )
    .expect("summarize zip archive");

    assert_eq!(summary.archives_scanned, 1);
    assert!(summary.archive_entries_scanned >= 1);
    assert!(
        summary
            .reports
            .iter()
            .any(|report| report.path.contains("bundle.zip!nested/sample_elf"))
    );
    assert!(
        summary
            .by_format
            .iter()
            .any(|item| item.format == BinaryFormat::Elf)
    );
}

#[test]
fn summarizes_tar_gz_archive_contents() {
    let root = temp_dir("targz");
    let archive_path = root.join("bundle.tar.gz");
    let pe_bytes = fs::read(fixture("sample_pe.exe")).expect("read pe fixture");
    let tar_bytes = make_tar_archive("payload/sample_pe.exe", &pe_bytes);
    let gzip_bytes = make_gzip_archive("bundle.tar", &tar_bytes);
    fs::write(&archive_path, gzip_bytes).expect("write tar.gz");

    let summary = public_summarize_path(
        &root,
        &AnalyzeOptions {
            include_yara: false,
            strings_interesting_only: true,
        },
    )
    .expect("summarize tar.gz archive");

    assert!(summary.archives_scanned >= 2);
    assert!(summary.archive_entries_scanned >= 1);
    assert!(summary.reports.iter().any(|report| {
        report
            .path
            .contains("bundle.tar.gz!bundle.tar!payload/sample_pe.exe")
    }));
    assert!(
        summary
            .by_format
            .iter()
            .any(|item| item.format == BinaryFormat::Pe)
    );
}

fn make_zip_archive(entry_name: &str, bytes: &[u8]) -> Vec<u8> {
    let compressed = compress_to_vec(bytes, 6);
    let name = entry_name.as_bytes();
    let local_offset = 0u32;

    let mut archive = Vec::new();
    archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    archive.extend_from_slice(&20u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&8u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    archive.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(name);
    archive.extend_from_slice(&compressed);

    let central_offset = archive.len() as u32;
    let mut central = Vec::new();
    central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    central.extend_from_slice(&20u16.to_le_bytes());
    central.extend_from_slice(&20u16.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&8u16.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&0u32.to_le_bytes());
    central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    central.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes());
    central.extend_from_slice(&0u32.to_le_bytes());
    central.extend_from_slice(&local_offset.to_le_bytes());
    central.extend_from_slice(name);

    let central_size = central.len() as u32;
    archive.extend_from_slice(&central);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&1u16.to_le_bytes());
    archive.extend_from_slice(&1u16.to_le_bytes());
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

fn make_tar_archive(entry_name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    write_field(&mut header[0..100], entry_name.as_bytes());
    write_field(&mut header[100..108], b"0000777\0");
    write_field(&mut header[108..116], b"0000000\0");
    write_field(&mut header[116..124], b"0000000\0");
    let size_field = format!("{:011o}\0", bytes.len());
    write_field(&mut header[124..136], size_field.as_bytes());
    write_field(&mut header[136..148], b"00000000000\0");
    for byte in &mut header[148..156] {
        *byte = b' ';
    }
    header[156] = b'0';
    write_field(&mut header[257..263], b"ustar\0");
    write_field(&mut header[263..265], b"00");
    let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>();
    let checksum_field = format!("{:06o}\0 ", checksum);
    write_field(&mut header[148..156], checksum_field.as_bytes());

    let mut archive = Vec::new();
    archive.extend_from_slice(&header);
    archive.extend_from_slice(bytes);
    let padding = (512 - (bytes.len() % 512)) % 512;
    archive.extend(std::iter::repeat_n(0u8, padding));
    archive.extend(std::iter::repeat_n(0u8, 1024));
    archive
}

fn make_gzip_archive(inner_name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    archive.extend_from_slice(&[0x1f, 0x8b, 8, 0x08]);
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.push(0);
    archive.push(255);
    archive.extend_from_slice(inner_name.as_bytes());
    archive.push(0);
    archive.extend_from_slice(&compress_to_vec(bytes, 6));
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    archive
}

fn write_field(slot: &mut [u8], value: &[u8]) {
    let len = value.len().min(slot.len());
    slot[..len].copy_from_slice(&value[..len]);
}
