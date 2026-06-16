# Task: craft an exploit input (proof-carrying)

You are looking for a vulnerability you can **prove by execution**. The target is run as:

```
{run_command}
```

where `{input}` is replaced by the path to an input file you design. A finding counts ONLY if running the target on your input triggers the witness: **{witness}**. cannon will execute every candidate you produce and keep only those that reproduce the witness 2-of-3 times.

Source root (read-only): `{source_root}`
Focus: {focus_area}

## How to work

Read the source. Find an input that drives the program into the vulnerable state — a buffer overflow, an out-of-bounds access, a crash, or an injection that makes the program emit a detectable marker. Work out the exact bytes of that input.

## Output

For each candidate exploit, emit a block:

<crash_type>short classification (e.g. heap-buffer-overflow)</crash_type>
<file>the source file:line of the vulnerability</file>
<poc_b64>base64 of the exact input bytes</poc_b64>

Use `<poc_b64>` for binary inputs (base64-encode them). For purely textual inputs you may instead use `<poc>literal text</poc>`. Emit multiple candidates if you have them — cannon executes each and discards the ones that don't reproduce.
