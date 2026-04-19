use crate::model::{BinaryFormat, BinaryReport, Severity, SummaryReport};

pub fn render_terminal(report: &BinaryReport) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "{} {} ({})",
        style("binscope", "1;36"),
        style(&report.file_name, "1"),
        render_format(report.format)
    ));
    out.push(format!(
        "Risk score: {}  Size: {} bytes  SHA256: {}",
        render_risk_score(report.risk_score),
        report.size,
        report.sha256
    ));
    out.push(format!(
        "Machine: {}  Entry point: 0x{:x}  Sections: {}  Imports: {}  Strings: {} interesting / {} total",
        report.machine,
        report.entry_point,
        report.sections.len(),
        report.imports.len(),
        report.interesting_strings_count,
        report.all_strings_count
    ));

    if let Some(imphash) = &report.import_analysis.imphash {
        out.push(format!("Import hash: {imphash}"));
    }

    out.push(String::new());
    out.push(style("Findings", "1"));
    if report.findings.is_empty() {
        out.push("  none".to_string());
    } else {
        for finding in &report.findings {
            out.push(format!(
                "  [{}] {}: {}",
                render_severity(&finding.severity),
                finding.title,
                finding.detail
            ));
        }
    }

    out.push(String::new());
    out.push(style("Sections", "1"));
    for section in &report.sections {
        let suspicious = if section.suspicious {
            format!(" {}", style("suspicious", "1;31"))
        } else {
            String::new()
        };
        out.push(format!(
            "  {:<16} entropy {:>4.2} {}{}",
            section.name,
            section.entropy,
            histogram(section.entropy),
            suspicious
        ));
    }

    out.push(String::new());
    out.push(style("Imports", "1"));
    if report.import_analysis.libraries.is_empty() {
        out.push("  none".to_string());
    } else {
        for library in &report.import_analysis.libraries {
            out.push(format!(
                "  {:<24} {} symbols",
                library.name, library.symbol_count
            ));
        }
        if !report.import_analysis.suspicious_libraries.is_empty() {
            out.push(format!(
                "  suspicious libraries: {}",
                report.import_analysis.suspicious_libraries.join(", ")
            ));
        }
    }

    out.push(String::new());
    out.push(style("Suspicious Imports", "1"));
    if report.suspicious_import_combos.is_empty() {
        out.push("  none".to_string());
    } else {
        for combo in &report.suspicious_import_combos {
            out.push(format!(
                "  [{}] {} -> {}",
                render_severity(&combo.severity),
                combo.name,
                combo.matched.join(", ")
            ));
        }
    }

    out.push(String::new());
    out.push(style("Protections", "1"));
    if report.protections.is_empty() {
        out.push("  none".to_string());
    } else {
        for protection in &report.protections {
            let status = match protection.enabled {
                Some(true) => style("enabled", "92"),
                Some(false) => style("disabled", "1;31"),
                None => style("unknown", "90"),
            };
            out.push(format!(
                "  {:<20} {} {}",
                protection.name, status, protection.detail
            ));
        }
    }

    if let Some(rich) = &report.rich_header {
        out.push(String::new());
        out.push(style("Rich Header", "1"));
        out.push(format!(
            "  offset 0x{:x}  length {}  xor_key 0x{:08x}  fingerprint {}",
            rich.offset, rich.length, rich.xor_key, rich.fingerprint
        ));
        for entry in rich.entries.iter().take(8) {
            out.push(format!(
                "  build {:<5} product {:<4} count {:<6} {}",
                entry.build, entry.product_id, entry.count, entry.label
            ));
        }
    }

    out.push(String::new());
    out.push(style("Resources", "1"));
    if report.resources.is_empty() {
        out.push("  none".to_string());
    } else {
        for resource in report.resources.iter().take(8) {
            out.push(format!(
                "  {:<12} {:<20} {} bytes {}",
                resource.resource_type, resource.name, resource.size, resource.summary
            ));
        }
    }

    out.push(String::new());
    out.push(style("Packer Hits", "1"));
    if report.packer_hits.is_empty() {
        out.push("  none".to_string());
    } else {
        for hit in &report.packer_hits {
            out.push(format!(
                "  {} at 0x{:x}: {}",
                style(&hit.name, "1;31"),
                hit.offset,
                hit.description
            ));
        }
    }

    out.push(String::new());
    out.push(style("Interesting Strings", "1"));
    let interesting = report.carved_strings.iter().take(12).collect::<Vec<_>>();
    if interesting.is_empty() {
        out.push("  none".to_string());
    } else {
        for item in interesting {
            out.push(format!(
                "  [{}] 0x{:x} {}",
                style(&item.category, "33"),
                item.offset,
                item.value
            ));
        }
    }

    if !report.yara_candidates.is_empty() {
        out.push(String::new());
        out.push(style("YARA Seeds", "1"));
        for item in report.yara_candidates.iter().take(8) {
            out.push(format!("  {item}"));
        }
    }

    out.join("\n")
}

pub fn render_summary(summary: &SummaryReport) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "{} {}",
        style("binscope summary", "1;36"),
        style(&summary.root, "1")
    ));
    out.push(format!(
        "Scanned: {}  Analyzed: {}  Skipped: {}  Archives: {}  Archive entries: {}  Errors: {}",
        summary.scanned_files,
        summary.analyzed_files,
        summary.skipped_files,
        summary.archives_scanned,
        summary.archive_entries_scanned,
        summary.errors.len()
    ));

    out.push(String::new());
    out.push(style("Formats", "1"));
    if summary.by_format.is_empty() {
        out.push("  none".to_string());
    } else {
        for item in &summary.by_format {
            out.push(format!(
                "  {:<8} {}",
                render_format(item.format),
                item.count
            ));
        }
    }

    out.push(String::new());
    out.push(style("Highest Risk", "1"));
    if summary.highest_risk.is_empty() {
        out.push("  none".to_string());
    } else {
        for report in &summary.highest_risk {
            let findings = if report.findings.is_empty() {
                "no findings".to_string()
            } else {
                report.findings.join("; ")
            };
            out.push(format!(
                "  {} {} {}",
                render_risk_score(report.risk_score),
                report.file_name,
                findings
            ));
        }
    }

    if !summary.errors.is_empty() {
        out.push(String::new());
        out.push(style("Errors", "1"));
        for error in summary.errors.iter().take(8) {
            out.push(format!("  {}: {}", error.path, error.message));
        }
    }

    out.join("\n")
}

fn histogram(entropy: f64) -> String {
    let width = 24usize;
    let filled = ((entropy / 8.0) * width as f64)
        .round()
        .clamp(0.0, width as f64) as usize;
    let mut bar = String::with_capacity(width);
    for idx in 0..width {
        if idx < filled {
            bar.push('#');
        } else {
            bar.push('.');
        }
    }
    style(&bar, "34")
}

fn render_risk_score(score: u8) -> String {
    let text = format!("{score:>3}/100");
    match score {
        0..=24 => style(&text, "92"),
        25..=49 => style(&text, "93"),
        50..=74 => style(&text, "1;33"),
        _ => style(&text, "1;31"),
    }
}

fn render_severity(severity: &Severity) -> String {
    match severity {
        Severity::Low => style("low", "92"),
        Severity::Medium => style("medium", "93"),
        Severity::High => style("high", "1;33"),
        Severity::Critical => style("critical", "1;31"),
    }
}

fn render_format(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Pe => "PE",
        BinaryFormat::Elf => "ELF",
        BinaryFormat::MachO => "Mach-O",
    }
}

fn style(value: &str, code: &str) -> String {
    format!("\u{1b}[{code}m{value}\u{1b}[0m")
}
