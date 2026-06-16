# The permutation planner — signal-driven, human-gated, cost-estimated

cannon's salvo used to be a blind cross-product: `focus × variant × model × runs`, fired all at once. That's a shotgun. The permutation planner turns it into a **guided, affordable, steerable** barrage: evidence about the target *proposes* priced permutations, **you** approve them one at a time under a hard budget cap, and only approved proposals fire. Every run feeds its real cost back so the estimates sharpen.

```
 signals ──propose──▶ QUEUE ──you approve──▶ schedule ──fire──▶ findings
   │ commit archaeology    (priced,           (budget gate)    (ledger)
   │ threat-model graph     ranked,                 │
   │ threat-intel manifest  deduped)                └── actual cost ──▶ recalibrate $/round
   │ evolution (bred variants)                                          └── fitness ──▶ next generation
   └── your typed suggestions
```

## The four signals (generators)

Each **proposes** — none fire. A proposal carries a focus, a yield score, an estimated cost, and the salvo it would run.

| Signal | What it mines | Example proposal |
|---|---|---|
| **commit archaeology** (`commits`) | git history — past *security* fix commits + churn hotspots | *"Variant-hunt around the SQL injection fix (7088da1) — find the sibling the patch missed"* |
| **threat-model** (`threat-model`) | the repo trust-graph (`repo_map.json`) | *"Audit untrusted→datastore flow into `store:users_db`"* (ranked by asset value) |
| **threat-intel** (`threat-intel`) | dependency manifests + a footgun table (+ optional web CVE research) | *"Hunt unsafe deserialization in PyYAML usage"* |
| **evolution** (`evolution`) | breeds prompt variants; fitness = confirmed findings at this target | *"Evaluate evolved variant 'g2-0' (mutated from 'aggressive')"* |

**Incomplete-fix hunting** (commit archaeology) is the standout: a past security fix is a map to a bug class that lived here, and patches routinely fix one site and miss its siblings. cannon proposes a focused hunt around each historical fix for the variant it missed — the elite-bug-hunter technique (Project-Zero-style variant analysis), automated over *your* history.

## The queue (the human gate)

Generators drop proposals into `targets/<t>/.cannon/queue.json`. `cannon permute` walks them best-yield-first and you decide:

```
  ▸ P-001  commit-archaeology  ·  yield 0.95  ·  ~$0.75 (1 round)
    Variant-hunt around the SQL injection fix (7088da15)
    └ Commit 7088da15 touched 1 source file(s); a past security fix is a prime variant-analysis target.
    focus › INCOMPLETE-FIX HUNT. Commit 7088da15 fixed a SQL injection ("Fix SQL injection in /search endpoint")…
    budget › $0.00 committed of $5.00 cap · $0.00 spent · ~$0.750/round
  [k]ick · [s]kip · [d]efer · [a]pprove-all · [r]e-permute · [g]o fire · [q]uit · or type a suggestion ›
```

- **k**ick → approved (scheduled), if it fits under the budget cap; **s**kip → no; **d**efer → later.
- **a**pprove-all under the cap; **g**o fire the approved set now; **q**uit (approved stay queued for `cannon queue run`).
- **r**e-permute → regenerate proposals; or just **type a hunch** — *"focus on the auth middleware bypass"* — and it becomes a top-priority, user-directed proposal, queued next.

The **budget cap** (`--budget`) is enforced at approval (by estimate) and again at execution (by actual spend, between proposals). Estimates start from a prior and **self-calibrate**: after each fire, `$/round` moves toward the observed rate (EMA), so day-two estimates reflect your model and repo.

## Commands

```bash
# propose from signals, approve interactively, fire approved under a $5 cap
cannon permute <target> --budget 5.00

# pick signals; non-interactive (auto-approve under the cap); just plan (fire later)
cannon permute <target> --sources commits,threat-intel --yes
cannon permute <target> --sources commits,threat-model,threat-intel,evolution --plan-only
cannon permute <target> --research          # also research live CVEs for the stack (web)

cannon queue list  <target>                 # the whole queue: status, est$, yield, outcomes
cannon queue run   <target>                 # fire the approved set (deferred execution)
cannon queue budget <target> 10.00          # set (or, with 0, clear) the cost cap
cannon queue clear <target>                 # drop decided proposals, keep the live queue
```

## It works — a live run

`targets/permdemo/` is a tiny Flask app with a dependency manifest (Flask, PyYAML, requests) and **real git history** — a past *"Fix SQL injection in /search"* commit with `app.py` as a churn hotspot. Recreate the history with `sh targets/permdemo/setup-git.sh`, then one fire of the top proposal:

```
$ cannon permute permdemo --sources commits,threat-intel --budget 0.10 --yes
    commits            +3 proposal(s)      ← found the SQLi-fix commit + 2 churn hotspots
    threat-intel       +3 proposal(s)      ← PyYAML deser, Flask SSTI, requests SSRF
  ✓ --yes: auto-approved 1 under the cap   ← the $0.10 cap gated the rest
  ▶ P-001 · Variant-hunt around the SQL injection fix (7088da15)
  ✓ P-001: 3 finding(s) · actual $2.83 (est $0.06)   ← cost self-calibrated → $0.89/round
```

The ledger afterward:

```
F-001  CRITICAL  SQL injection in /profile endpoint (variant missed by the fix)   app.py:20
F-002  CRITICAL  SQL injection in /search endpoint still present                   app.py:13
F-003  CRITICAL  Remote code execution via yaml.load on request body              app.py:26
```

**F-001 is the payoff**: the `/search` fix never touched `/profile`, and the incomplete-fix hunt found exactly that sibling — the variant a diff-only review would sail past. (It also flagged the still-present `/search` SQLi and, as a bonus, the PyYAML RCE.)

## Caveats (honest)

- **A single in-flight proposal can overshoot the cap.** The gate stops *between* proposals; it can't halt a fire mid-flight. The demo's one proposal cost $2.83 against a $0.10 cap — but no further proposal fired, so the cap correctly bounded *additional* spend. Set caps with one proposal's cost in mind.
- **Estimates are only as good as the calibration.** The first run uses a prior ($0.75/round); after a few fires the EMA converges to your real rate.
- **Evolution and `--research` cost tokens to *propose*** (LLM mutation / web lookups), so they're opt-in; the other three generators propose for free (deterministic git/manifest/graph mining).
