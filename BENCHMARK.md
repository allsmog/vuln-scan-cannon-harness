# Benchmark — cannon vs Semgrep on OWASP BenchmarkJava

Honest, reproducible precision/recall for cannon against a labeled corpus, head-to-head
with Semgrep on identical code with the *same scorer*. Run on 2026-06-16, `sonnet`,
`static_review` detector.

## TL;DR

1. **On a fair single-file slice, cannon ≈ Semgrep** — slightly better precision
   (0.632 vs 0.600), both catch every real bug (recall 1.0). From one file, neither tool
   can resolve the false-positive traps, because the disambiguating fact isn't in the file.
2. **The differentiator is real and demonstrated.** Give cannon the *one* helper that
   makes a trap safe and its reasoning flips the call from "vuln" to "not vuln." Semgrep
   can't — even with the helper file right there, its dataflow won't trace a cross-file
   constant return. On the 2 traps where the safe-reason is a single helper, cannon goes
   from 2 false positives to **0**; Semgrep stays at 2.
3. **Naive context dumping hurt.** Feeding *all 15* helper files as context regressed raw
   precision (0.632 → 0.500): the agent started auditing the helpers and reporting real-ish
   bugs *in them* (e.g. SSL/TLS misconfig in `Utils.java`) that aren't in the label set.
   Context must be scoped as read-only taint-resolution reference, not a second scan target.

## Setup

- **Corpus:** a 20-case slice of [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava)
  — **12 real vulnerabilities + 8 false-positive traps** (real-but-safe lookalikes) across
  SQL injection, command injection, path traversal, LDAP injection, and XSS.
- **Labels:** ground-truth `true`/`false` + CWE per case, in each target's `labels.json`.
- **Scorer:** cannon's own (`src/bench.rs`) — a detection matches a label by
  `basename + line(±tolerance) + CWE`, greedy one-to-one. The **same scorer** grades both
  tools (`cannon measure --against <tool>.sarif`), so the comparison is apples-to-apples.
- **Tools:** cannon (`sonnet`, `static_review`); Semgrep OSS with the registry Java ruleset.

### What makes the traps hard

Every trap is byte-for-byte injection-shaped in the file you scan:

```java
String param = scr.getTheValue("BenchmarkTest00052");   // looks tainted
String sql = "{call verifyUserPassword('foo','" + param + "')}";
stmt.executeQuery(sql);                                  // classic SQLi sink
```

It is safe only because `SeparateClassRequest.getTheValue()` — *in another file* — returns
a constant:

```java
public String getTheValue(String p) { return "bar"; }   // never the request param
```

Distinguishing the trap from the real bug requires **reading that helper and reasoning about
the value**. Pure pattern-matching / intraprocedural dataflow cannot.

> Caveat surfaced while building the slice: only **2 of the 8** traps (00051, 00052) are
> safe via this `getTheValue` constant. The other 6 are safe for *different* reasons. So the
> aggregate single-file numbers below are a floor, not a referendum on the differentiator —
> the controlled experiment isolates it.

## Results — single-file (each tool sees only the test file)

Apples-to-apples: both tools get exactly the one `BenchmarkTestNNNNN.java`.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep (OSS) | 12 | 8 | 0 | 0.600 | 1.000 | 0.750 |
| **cannon** (raw detector) | 12 | 7 | 0 | **0.632** | 1.000 | **0.774** |
| cannon (full pipeline, `--verify --votes 1`) | 11 | 6 | 1 | 0.647 | 0.917 | 0.759 |

Both tools flag all 12 real bugs. cannon's raw detector rejects one trap Semgrep doesn't.
The verifier trades a hair of recall (it disproved one real finding) for higher precision —
on `--votes 3` the recall loss tends to wash out, but votes=1 is the honest single-shot
number recorded here.

## The differentiator — controlled experiment

Isolate the one variable that matters: **can the tool read the helper that resolves the
trap?** Same two trap files (00051, 00052), three conditions. Repro corpora are in the repo:
`bench-traps-noctx/` and `bench-traps-ctx/`.

| Condition | What the tool can see | FP on the 2 traps | Precision |
|---|---|---:|---:|
| cannon, single-file | just `BenchmarkTestNNNNN.java` | 2 / 2 flagged | 0.000 |
| **cannon, + helper** | + `SeparateClassRequest.java` | **0 / 2 flagged** | **1.000** |
| Semgrep | helpers present in the tree | 2 / 2 flagged | — |

The only thing that changed between rows 1 and 2 is whether cannon could read
`SeparateClassRequest.java`. Given it, the find-agent reasons *"`getTheValue()` returns the
constant `"bar"`, so `param` is not attacker-controlled — no injection"* and **drops both
false positives**. Semgrep, even with the same file sitting in the repo, still flags both:
its OSS engine won't trace the cross-file constant return. **This is semantic reasoning
beating pattern-matching, demonstrated on identical code.**

```
$ cannon measure bench-traps-noctx --model sonnet     # single-file
  TOTAL  TP 0 FP 2 FN 0   precision 0.000
$ cannon measure bench-traps-ctx   --model sonnet     # + SeparateClassRequest.java
  TOTAL  TP 0 FP 0 FN 0   precision 1.000
```

## The honest caveat — context scoping

The obvious next step ("if one helper helps, feed *all* of them") **backfired.** Dumping all
15 `helpers/*.java` (2208 lines) into every target's `context/`:

| cannon raw | TP | FP | FN | Precision |
|---|---:|---:|---:|---:|
| single-file | 12 | 7 | 0 | 0.632 |
| + all 15 helpers | 12 | **12** | 0 | **0.500** |

Trap-resolution *improved* (it correctly rejected the `getTheValue` traps — 00052 returned
zero findings), but **9 new findings cited the helper files themselves** — e.g. genuine-looking
SSL/TLS misconfigurations in `Utils.java` (self-signed certs trusted, hostname verification
disabled) and issues in `LDAPManager.java`. Those aren't in the label set, so they score as
false positives and swamped the gain.

**Lesson (now reflected in how cannon feeds `context/`):** context is *evidence for resolving
taint*, not a second scan surface. The fixes are (a) feed the minimal relevant helper, not the
whole `helpers/` tree, and (b) constrain the finder to report only in the target file. The
single-file numbers above are therefore the honest default; `bench-owasp/` ships *without* a
helper dump for exactly this reason.

## How to reproduce

```bash
cargo build --release

# single-file head-to-head
./target/release/cannon measure bench-owasp --model sonnet --concurrency 6
semgrep --config p/java --sarif -o /tmp/semgrep.sarif bench-owasp/*/src
./target/release/cannon measure bench-owasp --against /tmp/semgrep.sarif

# the controlled differentiator experiment
./target/release/cannon measure bench-traps-noctx --model sonnet   # FP 2 (no helper)
./target/release/cannon measure bench-traps-ctx   --model sonnet   # FP 0 (+ helper)
```

## Honesty / limitations

- **Small slice** (20 cases). A signal, not a published-grade benchmark. Recall on a 12-bug
  set says little about hard-to-spot vulns.
- **One model** (`sonnet`), **one run** per case unless noted. cannon's output varies run to
  run; the salvo (`--runs`, `--variants`) exists to average that out and isn't exercised here.
- **Semgrep OSS**, not the Pro engine — Pro's interprocedural taint may trace some of these
  helpers. The comparison is "cannon vs the free Semgrep most people run," not "vs the best
  SAST money buys."
- **Cost & latency:** cannon is an LLM agent per file — seconds and tokens per case; Semgrep
  is sub-second and free. cannon's edge is reasoning over context Semgrep structurally can't
  use, not throughput.
- The verifier's recall dip (0.917) is from a single disproved real finding at `--votes 1`;
  treat full-pipeline precision/recall as indicative, not load-bearing, at this corpus size.
