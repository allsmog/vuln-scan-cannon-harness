# Task: mutate a vulnerability-hunting prompt into a new strategy

You are evolving a population of security-scanning prompts against a fitness function (how many real bugs each one gets *confirmed*). Below is the parent prompt **"{parent_name}"**. Produce a **mutated offspring**: a meaningfully *different* hunting strategy that might catch bugs the parent misses — while keeping the exact same placeholders and the same `<finding>` output contract so the rest of the pipeline still works.

Good mutations change the **strategy**, e.g.:
- adopt a sharper attacker persona, or a specific specialist lens (authz, crypto, deserialization, memory safety);
- reason sink-first instead of source-first (or vice versa);
- bias toward a particular bug class while staying open to others;
- add a concrete heuristic ("grep every raw string concatenation into a query first");
- get more aggressive about reporting borderline cases, or more conservative.

## Parent prompt ("{parent_name}")

{parent_prompt}

## Rules

- Keep **every** `{placeholder}` token that appears in the parent verbatim — `{source_root}`, `{language}`, `{focus_area}`, `{context}`.
- Keep the `<finding>…</finding>` output contract **exactly** (same tags, including `<taint_status>` and `<taint_path>`), so the parser still works.
- Change the strategy, not the format. Make it genuinely distinct from the parent — not a paraphrase.

## Output

<variant_prompt>
the full mutated prompt in markdown, ready to drop in as `find.md`
</variant_prompt>
