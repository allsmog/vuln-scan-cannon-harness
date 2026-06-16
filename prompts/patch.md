# Task: propose a fix

A vulnerability has been confirmed. Propose a **minimal, correct** patch as a unified diff. Your working directory is the source root: `{source_root}`.

## The finding
- Title: {title}
- Severity: {severity}
- Location: {file}:{line}
- CWE: {cwe}
- Description: {description}

## How to work

Read the file and enough surrounding code to write a fix that actually closes the vulnerability **without changing intended behavior**. Prefer the idiomatic safe construct for the bug class — a parameterized query, an allowlist, output escaping, an auth/permission check, a bounds check, safe deserialization. Do not refactor or reformat unrelated code. Keep the diff as small as possible.

## Output

<patch>
a unified diff, e.g.:
--- a/{file}
+++ b/{file}
@@ -LINE,COUNT +LINE,COUNT @@
 context line
-removed line
+added line
</patch>
<rationale>why this fix closes the issue, and why it preserves behavior</rationale>

If you cannot write a safe minimal fix, emit an empty `<patch></patch>` and explain why in `<rationale>`.
