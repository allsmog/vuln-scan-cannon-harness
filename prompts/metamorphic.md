# Task: metamorphic check of a finding

Prove or disprove this finding by **perturbation**. A safe-but-suspicious piece of code is safe because of one *load-bearing* fact — a helper returns a constant, a validator runs first, a branch is unreachable, a type can't carry the payload. Find that fact, then ask: *what is the minimal change that would make this genuinely exploitable, and does the real code already differ exactly there?*

Your working directory is the source root: `{source_root}`.

## The finding

- **Title:** {title}
- **Severity (claimed):** {severity}
- **CWE:** {cwe}
- **Location:** {file}:{line}
- **Description:** {description}
- **Evidence:** {evidence}

## Method

1. Read the cited code and everything that determines whether the dangerous operation is actually exploitable — follow values across files.
2. Identify the **load-bearing control**: the single thing that, if changed, flips this between safe and vulnerable (e.g. `getTheValue()` returning a constant instead of the request parameter; an `escape()` call; an `if isAdmin` guard).
3. State the **minimal mutation** that would make it exploitable.
4. Decide two facts:
   - **orig_vulnerable** — does the bug fire in the code *as written*?
   - **mutant_vulnerable** — would it fire *after* that minimal mutation?

The logic that follows: orig fires → REAL. orig safe but mutant fires → the control is load-bearing and effective → FALSE_POSITIVE. Neither fires → your mutation was the wrong lever (INCONCLUSIVE) — pick a better one.

{exec_note}

## Output

<mutation>the minimal code change that flips safe↔vulnerable (a tiny diff or one-line description)</mutation>
<orig_vulnerable>yes|no</orig_vulnerable>
<mutant_vulnerable>yes|no</mutant_vulnerable>
<reasoning>name the load-bearing control and why each boolean holds, grounded in the code</reasoning>

If (and only if) execution is enabled and you can express the check as a self-contained command, also emit:

<run_command>a shell command (may use {src}) whose witness fires ONLY when the bug is live</run_command>
<witness>crash | exit_nonzero | exit_code:N | output_contains:PAT</witness>
<mutation_file>path/relative/to/source/root.ext</mutation_file>
<mutation_find>exact code substring to replace (the load-bearing control)</mutation_find>
<mutation_replace>the replacement that removes the control</mutation_replace>
