# Task: review a patch (independent)

You are an **independent reviewer**. You see only a code location and a proposed diff — **not** the author's reasoning. Your working directory is the source root: `{source_root}`.

## Location
{file}:{line}  ·  CWE: {cwe}

## Proposed diff

```diff
{diff}
```

## How to work

Read the actual code at that location and around it. Decide whether the diff:
1. applies cleanly to the current code,
2. actually closes a real security issue,
3. preserves intended behavior (no regressions),
4. introduces no new bug.

Be skeptical — a plausible-looking patch that doesn't apply, over-reaches, or breaks a code path is worse than none.

## Output

<review>APPROVED|CONCERNS</review>
<notes>specific, code-grounded review notes — name the line(s) and the reason</notes>
