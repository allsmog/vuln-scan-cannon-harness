"""Mermaid emitters — the visualization surface.

No UI server, no canvas: Mermaid-in-Markdown renders in GitHub, VS Code, Obsidian
and most doc viewers, and the underlying JSON is there for a real UI later. This
is the lightweight, version-controllable answer to "visualizing threat models
and attack chains."
"""
from __future__ import annotations

import re

from .artifacts import Chain, TriagedFinding


def _node_id(name: str, prefix: str = "n") -> str:
    h = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_") or "x"
    return f"{prefix}_{h[:32]}"


def _esc(s: str) -> str:
    return (s or "").replace('"', "'").replace("\n", " ").strip()


def threat_model_mermaid(components, flows, boundaries) -> str:
    """flowchart of components + data flows, grouped by trust where given."""
    if not components and not flows:
        return ""
    lines = ["```mermaid", "flowchart LR"]

    # Group components into trust subgraphs when trust labels exist.
    by_trust: dict[str, list] = {}
    for c in components:
        by_trust.setdefault(c.trust or "system", []).append(c)

    declared: set[str] = set()
    for trust, comps in by_trust.items():
        if trust and trust != "system":
            lines.append(f'  subgraph {_node_id(trust, "tb")}["{_esc(trust)}"]')
            indent = "    "
        else:
            indent = "  "
        for c in comps:
            nid = _node_id(c.name)
            declared.add(c.name)
            lines.append(f'{indent}{nid}["{_esc(c.name)}"]')
        if trust and trust != "system":
            lines.append("  end")

    for fl in flows:
        a, b = _node_id(fl.src), _node_id(fl.dst)
        # Declare any endpoint not already a known component.
        if fl.src not in declared:
            lines.append(f'  {a}["{_esc(fl.src)}"]'); declared.add(fl.src)
        if fl.dst not in declared:
            lines.append(f'  {b}["{_esc(fl.dst)}"]'); declared.add(fl.dst)
        if fl.label:
            lines.append(f'  {a} -->|"{_esc(fl.label)}"| {b}')
        else:
            lines.append(f"  {a} --> {b}")

    lines.append("```")
    return "\n".join(lines)


def chains_mermaid(chains: list[Chain]) -> str:
    """One left-to-right path per chain: premise → step → … → impact."""
    if not chains:
        return ""
    lines = ["```mermaid", "flowchart LR"]
    for ci, c in enumerate(chains):
        sg = _node_id(c.title, f"c{ci}")
        lines.append(f'  subgraph {sg}["{_esc(c.title)} ({c.severity})"]')
        prev = f"{sg}_start"
        lines.append(f'    {prev}(["{_esc(c.premise or "attacker start")[:60]}"])')
        for si, step in enumerate(c.steps):
            nid = f"{sg}_s{si}"
            label = step.action or step.title or "step"
            lines.append(f'    {nid}["{_esc(label)[:70]}"]')
            lines.append(f"    {prev} --> {nid}")
            prev = nid
        end = f"{sg}_impact"
        lines.append(f'    {end}(["💥 {_esc(c.impact or "impact")[:60]}"])')
        lines.append(f"    {prev} --> {end}")
        lines.append("  end")
    lines.append("```")
    return "\n".join(lines)


def triage_table(triaged: list[TriagedFinding]) -> str:
    """Markdown table of triaged findings, ranked."""
    if not triaged:
        return "_No findings._"
    rows = ["| Rank | Sev | Verdict | Conf | Corrob | Finding | Location |",
            "|---:|---|---|---:|---:|---|---|"]
    for i, t in enumerate(triaged, 1):
        f = t.accumulated.representative
        loc = f.file + (f":{f.line}" if f.line else "")
        mark = "✅" if t.confirmed else ("❌" if t.verdict.verdict == "FALSE_POSITIVE" else "❔")
        rows.append(
            f"| {i} | {t.accumulated.max_severity} | {mark} {t.verdict.verdict} | "
            f"{t.verdict.confidence:.2f} | {t.accumulated.corroboration} | "
            f"{_esc(f.title)} | `{_esc(loc)}` |"
        )
    return "\n".join(rows)
