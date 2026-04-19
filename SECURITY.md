# Security Policy

## Supported versions

The project is young, so the latest release and the `main` branch receive security fixes first.

| Version | Supported |
| --- | --- |
| latest release | yes |
| `main` | yes |
| older releases | no |

## Reporting a vulnerability

Please avoid opening a public GitHub issue for security-sensitive reports.

Use one of these paths instead:

1. Open a private GitHub security advisory for this repository if that option is available to you.
2. If private advisory flow is unavailable, contact the maintainer directly and include:
   - a short summary of the issue
   - affected version or commit
   - reproduction steps
   - expected impact
   - any proof-of-concept details needed to validate the report

## What to expect

- You should receive an acknowledgement after the report is reviewed.
- Valid reports will be investigated and fixed as quickly as practical.
- Public disclosure is best delayed until a fix or mitigation is available.

## Scope notes

`binscope` is a static analysis tool and does not intentionally execute analyzed binaries, but parser bugs, denial-of-service inputs, and malformed binary handling issues are still in scope for responsible disclosure.
