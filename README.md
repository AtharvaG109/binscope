# binscope

`binscope` is a Rust CLI for triaging PE, ELF, and Mach-O binaries, spotting packer signals, carving strings, and generating YARA rule skeletons that analysts can refine further.

## Features

- Parses PE, ELF, and Mach-O binaries with the `object` reader API
- Computes Shannon entropy per section and per 256-byte block
- Flags suspicious import combinations such as `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread`
- Builds import fingerprints, including a PE-oriented `imphash`-style MD5
- Carves ASCII and UTF-16LE strings, then classifies URLs, IPs, registry keys, file paths, crypto terms, and suspicious WinAPI references
- Detects common packer hints including UPX, Themida, MPRESS, ASPack, Petite, and suspicious section names
- Extracts PE Rich headers and basic PE resource metadata
- Reports ELF hardening signals such as PIE, NX, RELRO, stripped state, interpreter, and `DT_NEEDED`-like dependency hints
- Emits a color terminal report and machine-friendly JSON
- Generates a YARA rule skeleton from recovered strings, entropy, and import fingerprints
- Summarizes whole directories with an aggregate risk overview

## Install

```bash
cargo install --path .
```

## Usage

```bash
binscope analyze /path/to/binary
binscope analyze /path/to/binary --json
binscope analyze /path/to/binary --yara
binscope analyze /path/to/binary --strings-interesting-only
binscope summarize /path/to/folder
binscope summarize /path/to/folder --json
```

## Local validation

```bash
cargo fmt
cargo check --offline
cargo test --offline
```

## Fixture-backed tests

Clean sample binaries live in [`testdata/fixtures`](./testdata/fixtures):

- `sample_pe.exe`
- `sample_elf`
- `sample_macho`

They are intentionally benign fixtures used for parser and reporting coverage in CI.

## Example output

```text
binscope sample_pe.exe (PE)
Risk score:  68/100  Size: 65536 bytes  SHA256: 1d1f...
Machine: X86_64  Entry point: 0x14b0  Sections: 4  Imports: 52  Strings: 14 interesting / 173 total
Import hash: 2f3f...

Findings
  [critical] Suspicious API combo: injector: Classic remote-thread injection chain
  [high] High-entropy section .packed: Entropy 7.91 suggests compression, encryption, or packed payloads
  [medium] Suspicious import libraries: kernel32.dll, ntdll.dll
```

## Test data

The [`testdata`](./testdata) directory contains two things:

- `fixtures/`: clean binaries committed to the repo for automated tests
- `samples.json`: metadata-only hashes and references for real-world families or packers

No live malware samples are stored in this repository.

## Finding files to test

Fastest options:

- Use the committed fixtures in [`testdata/fixtures`](./testdata/fixtures)
- Run the finder script against folders you already have

```bash
chmod +x scripts/find-test-binaries.sh
./scripts/find-test-binaries.sh ~/Downloads
./scripts/find-test-binaries.sh /path/to/windows/files /path/to/linux/files
```

Known working files on this machine during development were:

- `/Users/atharvagham/Downloads/rev_satellitehijack/satellite`
- `/Users/atharvagham/Downloads/job_scout_opt_starter/.venv/lib/python3.11/site-packages/setuptools/cli.exe`
- `/usr/bin/true`

Then analyze one with:

```bash
binscope analyze testdata/fixtures/sample_pe.exe
binscope analyze testdata/fixtures/sample_elf --json
binscope analyze testdata/fixtures/sample_macho --strings-interesting-only
binscope summarize testdata/fixtures --json
```

## Publishing on GitHub

Recommended publish flow:

```bash
git init
git add .
git commit -m "Initial binscope release"
gh auth login
gh repo create binscope --public --source=. --remote=origin --push
```

If you already created the repository on GitHub, connect it like this:

```bash
git remote add origin git@github.com:<your-user>/binscope.git
git push -u origin main
```

This repo includes a GitHub Actions workflow at [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) so pushes and pull requests automatically run formatting, build, and tests.

## Notes

- `binscope` is a static triage tool. It does not execute binaries.
- The PE `imphash` implementation here is intentionally lightweight and transparent rather than trying to mirror every edge case from other ecosystems.
- This implementation uses the locally cached `object` crate instead of `goblin` so the project can build in an offline environment.
