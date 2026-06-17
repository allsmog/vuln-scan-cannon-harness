# 🜂 cannon — the AI security harness that *reasons*

[![CI](https://github.com/allsmog/vuln-scan-cannon-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/allsmog/vuln-scan-cannon-harness/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/allsmog/vuln-scan-cannon-harness)](https://github.com/allsmog/vuln-scan-cannon-harness/releases)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)

> **AI-native SAST in a single Rust binary** — a *reasoning* layer that complements pattern scanners: agentic interprocedural taint resolution, a trust-graph reachability oracle, and metamorphic verification (**[benchmarked against Semgrep](BENCHMARK.md)** — roughly at parity on raw detection; the edge is reasoning over context and rejecting false positives), plus a human-gated, cost-estimated **[permutation planner](PERMUTATION.md)** with *incomplete-fix variant hunting*. An LLM security scanner that runs on your local Claude CLI — **your code never leaves your machine.**
>
> <sub>repo: `vuln-scan-cannon-harness` · keywords: AI SAST · LLM security scanner · semantic SAST · Semgrep complement · variant analysis · DevSecOps · AppSec</sub>

> [!IMPORTANT]
> **What to expect.** cannon is LLM-driven, so it is **non-deterministic** — the same scan can surface different findings run-to-run (that's what `--runs`/`--variants` and the adversarial verifier are for: sample and corroborate). Each run **spends tokens and takes seconds-to-minutes per file** via your local `claude` CLI; every run prints its `$cost`. Treat auto-triage (`triaged_by: auto`) as advice and apply human review before acting — especially on code you don't control (see [SECURITY.md](SECURITY.md)).

Fire **salvos of permuted "defending-code" scans** at a single target, then
**accumulate → triage → attack-chain → visualize** — managed through a persistent
findings ledger and a **Ratatui cockpit** that draws the threat model and attack
chains natively in your terminal.

A single self-contained **Rust binary** (`cannon`). The actual security reasoning
is delegated to your local, already-authenticated `claude` CLI — cannon orchestrates
it (async), accumulates and de-dupes, runs an adversarial verifier, and manages the
findings lifecycle.

Forked in *shape* from Anthropic's
[defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness):
modular stages, JSON checkpoints + `--resume`, a load-bearing adversarial verifier.
Deliberately **no broker, no database, no LLM prompt-compiler** — prompts are plain
editable files; the permutation matrix is the "mutation" surface; the ledger and
on-disk JSON/Markdown are the whole state.

```
feed context → threat-model → CANNON (salvo of permuted scans) → accumulate → triage → LEDGER → attack-chain → cockpit
 (code +       (THREAT_MODEL.md  (focus × variant × model × runs)  (union+dedup) (adversarial  (VULN_     (over triaged  (Ratatui:
  design docs)  + graph + focus)                                                  verify+rank) FINDINGS.md) findings)      native graphs)
```

**Docs:** [The permutation planner](PERMUTATION.md) · [Benchmark vs Semgrep](BENCHMARK.md) · [How it works (sequence diagram)](docs/how-it-works.html)

## Prerequisites

cannon does not call any API itself — it drives the **[Claude Code](https://docs.claude.com/en/docs/claude-code) `claude` CLI** on your machine. Before using cannon you need:

1. **Install the `claude` CLI** (Claude Code) and make sure it's on your `PATH`.
2. **Authenticate it once:** run `claude` (or `claude /login`) and sign in. cannon reuses that session — **no API key is set in cannon.**
3. **Verify it works:** `claude -p "say hi"` should print a reply. If that works, cannon works.
4. A recent **Rust toolchain** (≥ 1.88) to build the binary.

> If `claude` isn't installed/authenticated, cannon fails fast with `spawn failed (is `claude` installed and on PATH?)`. Point cannon at a specific binary with `CANNON_CLAUDE_BIN=/path/to/claude`.

## Install

```bash
cargo build --release          # → target/release/cannon  (one binary, no runtime deps)
# cannon reads its prompts from ./prompts (or $CANNON_PROMPTS); run from the repo
# root, or set CANNON_PROMPTS to the bundled prompts dir.
```

Prebuilt binaries for Linux/macOS/Windows are attached to each [GitHub Release](https://github.com/allsmog/vuln-scan-cannon-harness/releases) (extract and run; the `prompts/` dir is bundled alongside).

(Build the Python prototype under `reference-python/` only if you want the original; the Rust binary is the product.)

## The workflow

```bash
# 1. Fire: threat-model first (seeds focus + graph), salvo, triage, chain, merge to ledger.
cannon fire canary --threat-model --chain

# 2. Manage findings (three interchangeable ways, all write the one ledger):
cannon tui canary                                   #   the cockpit — browse + triage + graphs
cannon findings set canary F-006 --status false_positive --note "behind gateway"
$EDITOR targets/canary/VULN_FINDINGS.md  &&  cannon findings sync canary

# 3. Chain whatever you've triaged as real:
cannon chain canary                                 #   default scope = confirmed
cannon chain canary --scope triaged                 #   widen
```

## The cockpit (`cannon tui <target>`)

Three panes over the same in-process ledger — graphs drawn **natively** with
Ratatui's `Canvas`/braille (no browser; works in Warp, which has no inline-image
protocol):

```
┌ findings · canary (10) ───────────────┬ threat model  (Tab→chains) ───────────┐
│▶ F-001 CRITICAL confirmed  SQLi …      │  (trust-tier columns: untrusted →      │
│  F-006 HIGH     false_pos  binding …   │   trusted-core → datastore, drawn       │
│  …                                     │   with braille edges)                   │
├ detail ────────────────────────────────┼─────────────────────────────────────────┤
│ F-001 CRITICAL confirmed (auto)        │ attack chains (Tab) = braille lanes:     │
│ app.py:30 · CWE-89 · verifier REAL 1.0 │   start ▸ step ▸ step ▸ 💥 impact        │
└────────────────────────────────────────┴─────────────────────────────────────────┘
 ↑↓ move · c/f/a/x triage · e note · Tab graph · r regen chains · g open HTML · q quit
```

Keys: **c**onfirm / **f**alse-positive / **a**ccept / fi**x**ed set status live;
**e** edit note; **Tab** toggles threat-model ↔ chains; **r** recomposes chains over
the confirmed set; **g** opens a rendered Mermaid HTML (fallback for huge graphs); **q** quits.

## The ledger (`VULN_FINDINGS.md` + `.cannon/ledger.json`)

Persistent, per-target, survives runs. `ledger.json` is canonical; `VULN_FINDINGS.md`
is the human-facing render whose **status token round-trips**:

```markdown
### F-002 · CRITICAL · OS command injection in /ping
<!-- cannon:status=confirmed -->     ← edit by hand → `cannon findings sync`
- file: `app.py:50` · cwe: CWE-78 · ×2 rounds · verifier: REAL (0.99) · triaged_by: auto
- note:
```

- **Status vocabulary:** `new | confirmed | false_positive | accepted | fixed | duplicate`. "Triaged" = anything ≠ `new`.
- **Stable ids** (`F-001`…), assigned once, never renumbered.
- **Sticky human decisions:** re-running `fire`/`ingest` refreshes evidence and corroboration but **never overwrites** a status you set by hand (`triaged_by: human`). New findings are seeded from the verifier's verdict (`triaged_by: auto`) so `fire --chain` works out of the box; you keep final say.

## Commands

The CLI *is* the flow: **aim → fire → triage → manage → prove → chain → fix → measure**.

```
# AIM
cannon aim    <target>                 # threat model + focus areas (+ Mermaid graph)
cannon map    <target>                 # repo trust-graph → reachability oracle for the verifier
# PLAN  (signal-driven, human-gated, cost-estimated permutation — see PERMUTATION.md)
cannon permute <target> [--budget $] [--sources commits,threat-model,threat-intel,evolution]
                        [--research] [--yes] [--plan-only]
cannon queue  list|run|budget|clear <target>     # the proposal queue
# FIRE
cannon fire   <target> [--threat-model] [--repo-map] [--chain] [--dedup] [--diff <git-ref>]
                       [--detector static_review|secrets|dynamic] [--votes N]
                       [--runs N] [--focus "a;b"] [--variants …] [--models …] [--resume DIR]
# TRIAGE
cannon triage <target> [--all] [--votes N]            # (re)verify the ledger's findings
# MANAGE
cannon manage <target>                 # the Ratatui cockpit (/ filter, source-snippet pane)
cannon findings list|set|sync <target> # CLI ledger ops (set F-NNN --status confirmed …)
cannon seed   <target> <file...> [--format auto|sarif|semgrep|json|csv] [--verify]
cannon ingest <target> <results_dir>   # merge an existing run's triage.json
# PROVE
cannon prove  <target>                 # dynamic detector — reproduce by execution (CANNON_ALLOW_EXEC=1)
cannon metamorphic <target> [--scope review] [--apply]  # perturb the code to prove safe-vs-vulnerable
# CHAIN
cannon chain  <target> [--scope confirmed|accepted|triaged]
cannon fleet  <fleet.yaml>             # cross-service attack chains
# FIX
cannon fix    <target> [--scope confirmed] [--top N]  # draft patches + independent review
# MEASURE
cannon measure <corpus> [--verify] [--against tool.sarif] [--gate] [--write-baseline]
cannon tune    <corpus> --variants a,b,c [--holdout 0.5]  # optimize prompts on a train/test split
# output
cannon report <results_dir>            # re-render REPORT.md (+ report.sarif)
```

> Renamed; old names still work as **deprecated aliases**: `threat-model`/`recon` → `aim`, `verify` → `triage`, `tui` → `manage`, `patch` → `fix`, `bench` → `measure`.

### Reasoning over context — cannon's edge (see [`BENCHMARK.md`](BENCHMARK.md))

The benchmark showed raw detection is ~parity with Semgrep; cannon's edge is *semantic reasoning over the right context*. Four mechanisms lean into that:

- **Agentic interprocedural taint resolution** (find stage): the finder must **trace each candidate across files** — following a value into a helper in another file and reading what it actually returns — before reporting. It records the resolved path (`source → … → sink`) and an outcome. If its own trace lands on a constant / sanitizer / dead end, the finding is **dropped, not reported** (the OWASP `getTheValue()`-returns-`"bar"` trap dies here). Recall-safe: only self-disproved findings are dropped.
- **Repo-scale trust-graph oracle** (`cannon map`, `fire --repo-map`): builds a once-per-repo call/route/trust graph (`repo_map.json`), then the verifier asks it — deterministically — *"is this sink reachable from an untrusted entry point?"* A "no path" answer is a strong false-positive signal the verifier weighs (but still confirms against code). The threat model becomes a machine oracle, not just a picture.
- **Metamorphic verification** (`cannon metamorphic`): proves safe-vs-vulnerable by **perturbation** — synthesize the minimal mutation that *would* make it exploitable; if the code is safe but the mutation makes it fire, the safety is load-bearing → FALSE_POSITIVE; if it fires as-written → REAL. With `CANNON_ALLOW_EXEC=1` it materializes the mutant and *runs* original vs. mutant for a measured verdict. `--apply` writes verdicts back (non-human findings only).
- **Multi-vote, perspective-diverse verifier** (`--votes`, default 3): each finding is judged by independent skeptics using *reachability*, *exploitability*, and *mitigation* lenses; majority wins. It now also gets the finder's taint path and the graph oracle as inputs. Reports access level + preconditions, from which cannon **re-derives severity** instead of trusting the finder's claim.

### Other verification machinery

- **Semantic dedup** (`--dedup`): an LLM judge collapses cross-location duplicates the signature pass missed.
- **SARIF out**: every run writes `report.sarif`; the ledger writes `findings.sarif` — standard SARIF you can wire into GitHub code scanning yourself (add a `github/codeql-action/upload-sarif` step to your workflow). cannon doesn't ship that workflow for you.
- **Diff mode** (`--diff <ref>`): scope a salvo to files changed since a git ref (PR review).
- **Cost line**: each run prints `$cost (in/out tokens)`.
- **Git-history context**: recent commits are fed to the agents as evidence.

## Seed an existing backlog

Already have findings from another scanner (CodeQL, Semgrep, a SARIF export, a
bug-bounty spreadsheet)? Pour them into the ledger, then let cannon's adversarial
verifier disprove what it can — the reference harness's "feed it your backlog
first" move:

```bash
cannon seed canary scan.sarif results.json findings.csv   # auto-detects format
cannon triage canary                                       # triage the imported (unverified) findings
```

Seeded findings enter as `new` / `triaged_by: imported`, deduped by signature
against what cannon already found (a match just adds the source tag, e.g.
`sources: [cannon, sarif:CodeQL]`). `cannon triage` then runs the same
guilty-until-proven verifier over them and flips each to `confirmed` or
`false_positive`. Formats: **SARIF** (CodeQL/Semgrep/most tools), **Semgrep JSON**,
a **generic findings array**, and **CSV**.

## Detectors

A detector turns a target into findings; the registry (`src/detector.rs`) dispatches on `config.yaml`'s `detector:`:

- **`static_review`** (default) — an LLM agent reads source and reports findings.
- **`secrets`** — deterministic, **no LLM**: pattern rules (AWS/Stripe/GitHub/Slack/Google keys, private-key blocks, credential assignments) + a Shannon-entropy heuristic. Free and fast.
- **`dynamic`** — **proof-carrying**: an agent crafts an input, cannon *executes* the target and keeps the finding only if an executable **witness reproduces 2-of-3**. Config: `run_command` (with `{input}`/`{src}`), `witness` (`crash` | `exit_nonzero` | `exit_code:N` | `output_contains:PAT`), optional `build_command`. It executes target code, so it's gated behind **`CANNON_ALLOW_EXEC=1`** — run it in a sandbox/VM. Example: `targets/crasher/`.

## Benchmark (precision / recall) — `cannon measure`

Score cannon against a labeled corpus — each target carries a `labels.json` of ground-truth `{file,line,cwe}`:

```bash
cannon measure bench                       # detector-only (free on the secrets corpus)
cannon measure bench --verify              # full pipeline (find → verify → confirmed)
cannon measure bench-owasp --verify        # an OWASP-BenchmarkJava slice (real labels + FP-traps)
cannon measure bench-owasp --against semgrep.sarif   # score ANY tool's SARIF, same scorer
cannon measure bench --write-baseline      # pin the current F1 as the regression baseline
cannon measure bench --gate                # CI gate: exit 2 if F1 dropped below the baseline
cannon tune    bench --variants default,aggressive   # optimize prompts on a train/test split
```

**Self-tuning + regression gate** (`cannon tune`, `measure --gate`): the harness's premise is permuting/mutating prompts — now measured. `tune` evaluates each prompt variant's F1 on a **train split**, picks the best, and reports its F1 on a **held-out test split** (so a "win" isn't just overfitting). `measure --gate` fails CI (exit 2) when a prompt edit regresses F1 below a pinned baseline. The "mutation" surface stops being vibes.

Prints per-target + overall **TP/FP/FN, precision, recall, F1** and writes `bench.json`. Because `--against` scores an external tool's SARIF with cannon's *exact* scorer, you get an apples-to-apples **head-to-head vs Semgrep / CodeQL** on identical labeled code — the FP-trap cases (real-but-not-vulnerable lookalikes) are where semantic verification should beat pattern matching.

**Real numbers are in [`BENCHMARK.md`](BENCHMARK.md)** (OWASP BenchmarkJava, head-to-head vs Semgrep). The honest result: single-file, cannon ≈ Semgrep (P 0.632 vs 0.600, both recall 1.0); but in a controlled experiment, *given the one helper that makes a trap safe*, cannon's reasoning rejects false positives Semgrep flags even with the file present (2 FP → 0). Also documents where naive context-dumping **hurt** precision — context scoping matters.

## Fleet + cross-service chains

```bash
cannon fleet fleet.example.yaml
```

Scans every target, unions their **confirmed** findings (tagged by service), and composes attack chains that **span services** — the secret leaked by service A that unlocks the injection in service B.

## Learning from your triage

Every `false_positive` you record (CLI / md-edit / TUI) is fed into the verifier prompt as this repo's **known false-positive patterns**, so it grows more skeptical of the noise *your* team rejects over time — without auto-suppressing real bugs.

## A target

```
targets/<name>/
  config.yaml          # detector, language, description, focus_areas, engagement_context
  src/                 # the code to scan (or set source_root)
  context/             # design docs — auto-fed into prompts as evidence (not instructions)
  prompt_overrides/    # optional *.md shadowing ../../prompts for THIS target
  VULN_FINDINGS.md     # ← the managed ledger (generated; you edit status tokens)
  THREAT_MODEL.md      # ← generated narrative + graph
  .cannon/ledger.json  # ← canonical ledger state
```

## Permutation & prompt mutation

The salvo is the cross product `focus × variant × model × runs` — one target hit from
many angles, results unioned (the reference's "expect variance; union across runs",
weaponized). Each stage's prompt resolves highest-first:
`targets/<t>/prompt_overrides/<name>.md` → `prompts/variants/<variant>/<name>.md` →
`prompts/<name>.md`. Edit any of them and it's live next run; each round records the
prompt's `sha256` for provenance.

### The permutation planner — `cannon permute` (full writeup: [`PERMUTATION.md`](PERMUTATION.md))

Firing the whole cross-product blindly is a shotgun that can torch your budget. The
planner makes it **evidence-driven, human-gated, and cost-estimated**: four signal
generators *propose* priced permutations into a queue, you approve them one at a time
under a hard budget cap, and only approved proposals fire — with the cost estimate
**self-calibrating** from each run's actuals.

- **Signals:** **commit archaeology** (past security-fix commits → *incomplete-fix
  variant hunts* + churn hotspots), **threat-model** (the trust-graph → untrusted→sink
  flow audits ranked by asset value), **threat-intel** (dependency manifests → known
  footgun hunts, + optional live CVE research), and **evolution** (breeds prompt
  variants; fitness = confirmed findings here).
- **The gate:** `cannon permute` walks proposals best-yield-first — `[k]ick / [s]kip /
  [d]efer / [a]pprove-all / [r]e-permute / [g]o / [q]uit`, or **type a hunch** to seed a
  directed permutation. `--budget` caps spend; `--yes` is non-interactive; `--plan-only`
  queues without firing (run later via `cannon queue run`).
- **Proven live:** on a demo repo with a *"Fix SQL injection in /search"* commit, the
  incomplete-fix hunt found the **`/profile` SQLi the patch never touched** — the variant
  a diff-only review misses. State lives in `targets/<t>/.cannon/queue.json`.

## Layout

```
src/                 # the Rust crate
  agent.rs           # tokio `claude -p` wrapper: stream-json + resume/backoff
  runner.rs          # run_salvo — the single orchestration seam (semaphore + checkpoints + resume)
  ledger.rs          # the persistent findings ledger + VULN_FINDINGS.md round-trip
  stages/            # find · verify (adversary) · recon · threat_model · chain · report
  tui/               # app.rs draw/keys · graph.rs native canvas layout
prompts/             # editable prompt templates (+ variants/)
targets/             # per-target config, source, context, ledger
reference-python/    # the original verified Python prototype (kept as the spec)
```

## Scaling out (later)

The entire run-manager is one function, `runner::run_salvo` (async fan-out +
checkpoints). If you ever distribute rounds across machines, replace that one
function's body with a producer/consumer — every stage above and below stays
untouched. Not before you have multiple machines. `static_review` is the only
detector today (read-only `claude` tools, no execution); a `dynamic` sandboxed
detector would implement the same `run_round` behind a build/run sandbox + PoC.
