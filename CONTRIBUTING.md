# Contributing to cannon

Thanks for your interest. cannon is a single self-contained Rust binary that
orchestrates the local `claude` CLI — contributions that keep it small, fast, and
file-state-only (no broker, no DB, no prompt-compiler) are very welcome.

## Getting started

```bash
cargo build --release      # → target/release/cannon
cargo test                 # the deterministic cores are unit-tested (no LLM needed)
```

Most of cannon's logic is pure and tested without any API calls — the scorer,
the taint predicates, the trust-graph reachability, the metamorphic decision
table, the queue/budget math, and every permutation generator's core. Please add
tests for new deterministic logic.

## Where things live

- `src/runner.rs` — `run_salvo`, the single orchestration seam.
- `src/stages/` — find · verify · repomap · metamorphic · chain · report · …
- `src/detector.rs` — the detector registry (`static_review` · `secrets` · `dynamic`).
- `src/generators/` — the permutation signal generators (commits · threatmodel · intel · evolve).
- `src/queue.rs` — the human-gated, cost-estimated proposal queue.
- `prompts/*.md` — the editable prompt templates (the mutation surface).

## Ground rules

- **Keep it dependency-light.** New crates need a real justification.
- **Prompts are data, not code** — tune behavior in `prompts/` (or per-target
  `prompt_overrides/`) before reaching for code.
- **`cargo test` must stay green**, and please run `cargo build --release` before a PR.
- For behavior changes, a benchmark delta (`cannon measure bench`) or a note on
  why precision/recall is unaffected is appreciated.

## Reporting issues

Use the issue templates. For security-relevant findings *in cannon itself*, please
open a private advisory rather than a public issue.
