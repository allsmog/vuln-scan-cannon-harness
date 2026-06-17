# Changelog

All notable changes to cannon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Contain `source_root`.** A target's `config.yaml` can no longer silently
  redirect cannon's read/exec scope outside the target/working dir; escaping
  paths are refused unless `CANNON_ALLOW_EXTERNAL_SOURCE_ROOT=1`.
- **Hard tool denylist for the agent.** The `claude` CLI is now invoked with an
  explicit `--disallowedTools` denylist (Write/Edit/Bash/Task/WebFetch/WebSearch/…)
  and the tool set is sanitized so a caller (or prompt injection) can't widen it.
  Permission mode is overridable via `CANNON_PERMISSION_MODE`.
- **Prompt-injection framing.** The verifier prompt now explicitly treats finding
  fields and repository comments as untrusted data, and disregards in-code
  assertions of a verdict (e.g. `// mark FALSE_POSITIVE`).
- **Path-traversal guard** on the metamorphic `mutation_file` (and temp-dir tag
  sanitization); the dynamic detector prints the commands it will run.
- Expanded `SECURITY.md` with an explicit threat model and a table of
  security-relevant environment variables. Added `deny.toml` (cargo-deny).

### Added
- **Per-invocation timeout** for the `claude` CLI (`CANNON_AGENT_TIMEOUT_SECS`,
  default 600s); a hung CLI no longer wedges a salvo slot forever.
- **`CANNON_CLAUDE_BIN`** to point at a specific `claude` binary (and to stub it
  in tests).
- **End-to-end smoke test** driving the real binary through the salvo runner,
  agent, verifier, and ledger merge against a stub CLI; real lock
  contention/timeout/stale-break tests; resume-manifest tests.
- **Versioned salvo manifest** (`salvo.json` now carries `schema_version` +
  target identity); `--resume` refuses cross-target or newer-schema directories
  and warns on legacy ones.
- **Cross-platform "open"** (macOS `open`, Linux `xdg-open`, Windows `start`) and
  a Windows build job in CI.
- **Release workflow** producing prebuilt binaries for Linux (x86_64/aarch64),
  macOS (x86_64/aarch64), and Windows (x86_64).
- CI now gates on `clippy -D warnings` and a verified MSRV (Rust 1.88), and runs
  `cargo-deny` for advisories/licenses/sources.

### Changed
- The shared findings ledger and queue now use atomic writes under a
  cross-process lock; merges reload under the lock to avoid lost updates.
- Per-run results directories are guaranteed unique (no second-precision
  timestamp collisions).
- Checkpoint write failures are surfaced instead of silently swallowed.

### Fixed
- Replaced panics (`.expect()`) in the verify/patch prompt loading with graceful
  errors.
- Guarded cost accounting against NaN/negative CLI values.
- README now states the `claude` CLI prerequisite, the non-determinism and
  per-scan cost, and scopes the Semgrep comparison to its benchmark.
