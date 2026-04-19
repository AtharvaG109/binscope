use std::path::PathBuf;

use binscope::PublicAnalyzeOptions as AnalyzeOptions;
use binscope::{BinaryFormat, public_analyze_path, public_summarize_path};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("fixtures")
        .join(name)
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
}
