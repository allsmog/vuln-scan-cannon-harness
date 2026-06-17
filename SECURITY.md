# Security Policy

cannon is a tool for *finding* vulnerabilities — but it's also software, so it can
have its own.

## Reporting a vulnerability in cannon

Please **do not** open a public issue for a security flaw in cannon itself. Instead,
open a private report via GitHub's **[Security advisories](https://github.com/allsmog/vuln-scan-cannon-harness/security/advisories/new)**
(Security → Report a vulnerability), or email the maintainer.

Include enough to reproduce (version/commit, OS, and the trigger). I'll acknowledge
within a few days and coordinate a fix and disclosure timeline with you.

## Scope notes

- cannon runs your local, authenticated `claude` CLI and reads source you point it
  at; it does not exfiltrate code. The `dynamic` detector and `metamorphic --apply`
  paths **execute target code** and are gated behind `CANNON_ALLOW_EXEC=1` — run
  those only inside a sandbox or disposable VM.
- The `targets/` directory contains **intentionally vulnerable** demo code and
  **fake** secret fixtures for testing detectors. They are not real credentials.
