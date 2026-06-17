# Security Policy

cannon is a tool for *finding* vulnerabilities — but it's also software, so it can
have its own.

## Reporting a vulnerability in cannon

Please **do not** open a public issue for a security flaw in cannon itself. Instead,
open a private report via GitHub's **[Security advisories](https://github.com/allsmog/vuln-scan-cannon-harness/security/advisories/new)**
(Security → Report a vulnerability), or email the maintainer.

Include enough to reproduce (version/commit, OS, and the trigger). I'll acknowledge
within a few days and coordinate a fix and disclosure timeline with you.

## Threat model & trust boundaries

cannon scans source code that **you may not fully trust** (third-party repos, dependencies). Treat the following as the explicit trust model:

- **The LLM reads untrusted code.** The find/verify agents run your local `claude` CLI over the target source with a **read-only** toolset (Read/Grep/Glob), an explicit `--disallowedTools` denylist (Write/Edit/Bash/Task/WebFetch/WebSearch/…), and tool-set sanitization so a caller can't widen them. Comments/strings in the target are framed as untrusted *data* in the system and verifier prompts — but **prompt injection is not fully solvable.** Adversarial code can still attempt to influence a verdict; treat cannon's auto-triage (`triaged_by: auto`) as advice, and apply human review (`triaged_by: human`) before acting on findings in untrusted code.
- **`source_root` is contained.** A target's `config.yaml` cannot silently redirect cannon's read/exec scope outside the target dir (or your working tree); escaping paths are refused unless you set `CANNON_ALLOW_EXTERNAL_SOURCE_ROOT=1`.
- **Code execution is opt-in and isolated.** The `dynamic` detector and `metamorphic --apply` paths **execute target code and commands taken from the target's `config.yaml` via `sh -c`**. They are gated behind `CANNON_ALLOW_EXEC=1`, print the commands they will run, and contain LLM-supplied mutation paths against traversal — but the commands themselves are arbitrary by design. **Run these only inside a sandbox or disposable VM**, never on a host with secrets/credentials.
- **Transcripts may contain secrets.** Agent transcripts (`*.jsonl` under `.cannon/`/`results/`) capture the model reading real source and can include cleartext secrets present in the target. These are excluded by `.gitignore`; treat the `.cannon/`/`results/` dirs as sensitive and do not share them unscrubbed.

## Configuration knobs (security-relevant)

| Env var | Default | Effect |
|---|---|---|
| `CANNON_ALLOW_EXEC` | unset | Required (`=1`) to run the dynamic/metamorphic exec paths. |
| `CANNON_ALLOW_EXTERNAL_SOURCE_ROOT` | unset | Required (`=1`) to let a `config.yaml` point `source_root` outside the target/working dir. |
| `CANNON_AGENT_TIMEOUT_SECS` | `600` | Per-invocation wall-clock budget for the `claude` CLI (`0` disables). |
| `CANNON_PERMISSION_MODE` | `bypassPermissions` | Permission mode passed to the CLI; the denylist is the hard backstop. |
| `CANNON_NO_TRANSCRIPTS` | unset | Set (`=1`) to suppress agent transcripts (which may contain cleartext secrets read from the target). |
| `CANNON_CLAUDE_BIN` | `claude` | Path to the CLI binary (for pinning or testing). |

## Scope notes

- cannon runs your local, authenticated `claude` CLI and reads source you point it
  at; it does not exfiltrate code.
- The `targets/` directory contains **intentionally vulnerable** demo code and
  **fake** secret fixtures for testing detectors. They are not real credentials.
