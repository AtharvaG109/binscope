# JSON Output Notes

Use `--json` when you want `binscope` to feed another script or persist a triage snapshot.

## Analyze a single binary

```bash
binscope analyze /path/to/binary --json
```

## Summarize a folder

```bash
binscope summarize /path/to/folder --json
```

Recommended follow-up fields to inspect first:

- `risk_score`
- `packer_signals`
- `interesting_strings`
- `import_fingerprint`
- `hardening`
