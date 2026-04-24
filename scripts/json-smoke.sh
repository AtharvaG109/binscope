#!/usr/bin/env bash
set -euo pipefail

TARGET_PATH="${1:-testdata/fixtures/sample_elf}"
SUMMARY_PATH="${2:-testdata/fixtures}"

analyze_json="$(mktemp)"
summary_json="$(mktemp)"
trap 'rm -f "$analyze_json" "$summary_json"' EXIT

cargo run --quiet -- analyze "$TARGET_PATH" --json > "$analyze_json"
cargo run --quiet -- summarize "$SUMMARY_PATH" --json > "$summary_json"

python3 - "$analyze_json" "$summary_json" <<'PY'
import json
import sys

analyze_path, summary_path = sys.argv[1:]
with open(analyze_path, "r", encoding="utf-8") as handle:
    analyze = json.load(handle)
with open(summary_path, "r", encoding="utf-8") as handle:
    summary = json.load(handle)

required_report = {"path", "file_name", "format", "sha256", "risk_score", "findings"}
missing_report = required_report - analyze.keys()
if missing_report:
    raise SystemExit(f"analyze JSON missing keys: {sorted(missing_report)}")

required_summary = {"root", "scanned_files", "analyzed_files", "highest_risk", "reports"}
missing_summary = required_summary - summary.keys()
if missing_summary:
    raise SystemExit(f"summary JSON missing keys: {sorted(missing_summary)}")

if summary["analyzed_files"] < 1:
    raise SystemExit("summary JSON did not include any analyzed files")

print(
    "validated binscope JSON output: "
    f"{analyze['file_name']} plus {summary['analyzed_files']} summarized file(s)"
)
PY
