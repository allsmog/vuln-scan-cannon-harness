# Task: collapse duplicate findings

Below are vulnerability findings from multiple scan passes. Some describe the **same underlying bug** at slightly different locations or in different words. Identify groups that are genuinely the same root cause and fix.

## Findings

{findings_catalog}

## How to work

Only group findings that share the **same root cause and the same fix**. Two different bugs that merely live in the same file are NOT duplicates. The same injection reached via two endpoints that both flow into one vulnerable function IS a duplicate. When in doubt, do NOT group — over-merging hides real bugs.

## Output

For each group of 2+ duplicates, emit one block listing their bracketed signatures exactly as shown above:

<duplicate>sig-a, sig-b</duplicate>

Emit nothing for findings that are unique. If there are no duplicates, emit no blocks.
