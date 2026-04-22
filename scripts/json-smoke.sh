#!/usr/bin/env bash
set -euo pipefail

TARGET_PATH="${1:-testdata/fixtures/sample_elf}"

cargo run --quiet -- analyze "$TARGET_PATH" --json
