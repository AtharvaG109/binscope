# Triage Playbook

## Fast loop

1. Run `binscope analyze sample.bin`.
2. Check overall risk score and section entropy.
3. Review suspicious imports, carved strings, and packer hints.
4. Re-run with `--json` if you want to save or diff the result.
5. Generate a YARA skeleton only after you have high-signal strings.

## Useful combinations

```bash
binscope analyze sample.bin --strings-interesting-only
binscope analyze sample.bin --yara
binscope summarize malware-drop-folder --json
```

## Notes

- Treat generated YARA as a starting point, not a finished rule.
- Suspicious strings are strongest when they align with imports and entropy spikes.
- Archive summaries are a quick pre-filter before deeper reverse engineering.
