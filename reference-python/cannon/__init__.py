"""cannon — the vuln-scan-cannon-harness.

Fire salvos of permuted "defending-code" scans at a single target, then
accumulate → triage → attack-chain → visualize. Forked in *shape* from
Anthropic's defending-code-reference-harness: modular stages, JSON
checkpoints + resume, an adversarial verifier. No broker, no database, no
prompt-compiler — prompts are plain editable files and the permutation
matrix is the "mutation" surface.
"""

__version__ = "0.1.0"
