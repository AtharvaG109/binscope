use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryReport {
    pub path: String,
    pub file_name: String,
    pub format: BinaryFormat,
    pub size: u64,
    pub sha256: String,
    pub machine: String,
    pub entry_point: u64,
    pub image_base: Option<u64>,
    pub headers: HeaderInfo,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportEntry>,
    pub import_analysis: ImportAnalysis,
    pub suspicious_import_combos: Vec<SuspiciousImportCombo>,
    pub carved_strings: Vec<CarvedString>,
    pub all_strings_count: usize,
    pub interesting_strings_count: usize,
    pub yara_candidates: Vec<String>,
    pub rich_header: Option<RichHeaderReport>,
    pub resources: Vec<ResourceInfo>,
    pub protections: Vec<ProtectionCheck>,
    pub packer_hits: Vec<PackerHit>,
    pub findings: Vec<Finding>,
    pub risk_score: u8,
    pub yara_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderInfo {
    pub kind: String,
    pub architecture: String,
    pub entry_point: u64,
    pub image_base: Option<u64>,
    pub details: Vec<HeaderField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderField {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub file_offset: u64,
    pub file_size: u64,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub flags: Vec<String>,
    pub entropy: f64,
    pub block_entropies: Vec<f64>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportEntry {
    pub library: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportAnalysis {
    pub imphash: Option<String>,
    pub fingerprint_sha256: String,
    pub libraries: Vec<ImportLibrary>,
    pub suspicious_libraries: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportLibrary {
    pub name: String,
    pub symbol_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousImportCombo {
    pub name: String,
    pub severity: Severity,
    pub matched: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, Serialize)]
pub struct CarvedString {
    pub offset: u64,
    pub value: String,
    pub encoding: StringEncoding,
    pub category: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RichHeaderReport {
    pub offset: usize,
    pub length: usize,
    pub xor_key: u32,
    pub fingerprint: String,
    pub entries: Vec<RichHeaderEntryReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RichHeaderEntryReport {
    pub product_id: u16,
    pub build: u16,
    pub count: u32,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceInfo {
    pub resource_type: String,
    pub name: String,
    pub language: Option<u16>,
    pub size: u32,
    pub sha256: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionCheck {
    pub name: String,
    pub enabled: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackerHit {
    pub name: String,
    pub offset: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryReport {
    pub root: String,
    pub scanned_files: usize,
    pub analyzed_files: usize,
    pub skipped_files: usize,
    pub archives_scanned: usize,
    pub archive_entries_scanned: usize,
    pub errors: Vec<FileError>,
    pub by_format: Vec<FormatCount>,
    pub highest_risk: Vec<BinarySummary>,
    pub reports: Vec<BinarySummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinarySummary {
    pub path: String,
    pub file_name: String,
    pub format: BinaryFormat,
    pub risk_score: u8,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormatCount {
    pub format: BinaryFormat,
    pub count: usize,
}
