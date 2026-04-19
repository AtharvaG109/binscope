# Docs

This folder contains lightweight public-facing examples for the `binscope` repository.

## Example artifacts

- [Terminal report capture](./examples/sample-pe-report.txt)
- [PE JSON report](./examples/sample-pe-report.json)
- [Directory summary JSON](./examples/sample-summary.json)
- [Terminal snapshot SVG](./images/sample-pe-terminal.svg)

## Notes

- The text report capture includes ANSI color codes because it was generated from the real CLI.
- The JSON examples come from the committed clean fixtures in `testdata/fixtures/`.
- The SVG snapshot is a compact visual preview intended for documentation and repository browsing.
- `summarize` now descends into supported archives such as `zip`, `jar`, `tar`, `tgz`, and `tar.gz`.
