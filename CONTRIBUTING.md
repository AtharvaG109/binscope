# Contributing to binscope

Thanks for contributing.

## Development flow

1. Create a feature branch from `main`.
2. Make your changes in focused commits.
3. Run the local checks:

```bash
cargo fmt
cargo check --offline
cargo test --offline
```

4. Update documentation when behavior changes.
5. Open a pull request with a short explanation of:
   - what changed
   - why it changed
   - how it was tested

## Project expectations

- Keep the CLI output readable for analysts doing quick triage.
- Prefer deterministic JSON fields over loosely structured output.
- Avoid checking in unsafe or live malware samples.
- Add tests when changing parser behavior, scoring, or report shape.

## Test data policy

- `testdata/fixtures/` contains only clean committed fixtures.
- `testdata/samples.json` may contain malware hashes and references, but not the samples themselves.

## Pull request tips

- Keep changes scoped.
- Mention platform impact when changing PE, ELF, or Mach-O logic.
- Call out false-positive or false-negative tradeoffs when adjusting heuristics.
