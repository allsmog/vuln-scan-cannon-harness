"""Report stage: assemble human + machine artifacts from the accumulated,
triaged, chained results. Deterministic (no agent) — pure rendering.

Writes:
  REPORT.md                — the human report (threat model, triage, chains, viz)
  THREAT_MODEL.md          — narrative + Mermaid graph (when a threat model ran)
  triage.json              — ranked triaged findings
  findings_accumulated.json
  chains.json
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from ..artifacts import AccumulatedFinding, Chain, RoundResult, TriagedFinding
from ..viz import chains_mermaid, threat_model_mermaid, triage_table


def write_threat_model(results_dir: str, tm) -> str:
    p = Path(results_dir) / "THREAT_MODEL.md"
    graph = threat_model_mermaid(tm.components, tm.flows, tm.boundaries)
    parts = [f"# Threat model\n", tm.narrative or "_(no narrative emitted)_"]
    if graph:
        parts.append("\n## System / data-flow graph\n\n" + graph)
    if tm.boundaries:
        parts.append("\n## Trust boundaries\n\n" + "\n".join(f"- {b}" for b in tm.boundaries))
    if tm.focus_areas:
        parts.append("\n## Seeded focus areas\n\n" + "\n".join(f"- {a}" for a in tm.focus_areas))
    p.write_text("\n".join(parts) + "\n")
    (Path(results_dir) / "threat_model.json").write_text(json.dumps(tm.to_dict(), indent=2))
    return str(p)


def _strip_fences(s: str) -> str:
    """Remove a wrapping ```lang ... ``` fence so we don't nest code blocks."""
    s = s.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if len(lines) >= 2:
            lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            s = "\n".join(lines)
    return s.strip()


def _confirmed_detail(t: TriagedFinding) -> str:
    f = t.accumulated.representative
    loc = f.file + (f":{f.line}" if f.line else "")
    out = [
        f"### {f.severity} — {f.title}",
        f"- **Location:** `{loc}`",
        f"- **CWE:** {f.cwe or 'unspecified'}",
        f"- **Signature:** `{t.accumulated.signature}`",
        f"- **Corroboration:** {t.accumulated.corroboration} round(s) — {', '.join(t.accumulated.rounds)}",
        f"- **Verifier confidence:** {t.verdict.confidence:.2f}",
        "",
        f"{f.description}",
    ]
    if f.exploit_premise:
        out += ["", f"**Exploit premise:** {f.exploit_premise}"]
    if f.evidence:
        out += ["", "**Evidence:**", "", "```", _strip_fences(f.evidence)[:1500], "```"]
    if t.verdict.reasoning:
        out += ["", f"**Verifier reasoning:** {t.verdict.reasoning}"]
    return "\n".join(out)


def _chains_section(chains: list[Chain]) -> str:
    if not chains:
        return "_No multi-step chains composed._"
    parts = [chains_mermaid(chains), ""]
    for c in chains:
        parts.append(f"### {c.severity} — {c.title}")
        parts.append(f"- **Premise:** {c.premise}")
        parts.append(f"- **Impact:** {c.impact}")
        parts.append("- **Steps:**")
        for i, s in enumerate(c.steps, 1):
            ref = f" `[{s.signature}]`" if s.signature else ""
            parts.append(f"  {i}. {s.action}{ref}")
        parts.append("")
    return "\n".join(parts)


def write_report(
    results_dir: str,
    target_name: str,
    rounds: list[RoundResult],
    accumulated: list[AccumulatedFinding],
    triaged: list[TriagedFinding],
    chains: list[Chain],
    threat_model=None,
    salvo_size: int | None = None,
) -> str:
    rd = Path(results_dir)
    rd.mkdir(parents=True, exist_ok=True)

    # Machine-readable artifacts.
    (rd / "findings_accumulated.json").write_text(
        json.dumps([a.to_dict() for a in accumulated], indent=2))
    (rd / "triage.json").write_text(
        json.dumps([t.to_dict() for t in triaged], indent=2))
    (rd / "chains.json").write_text(
        json.dumps([c.to_dict() for c in chains], indent=2))

    status_counts = Counter(r.status for r in rounds)
    raw = sum(len(r.findings) for r in rounds)
    confirmed = [t for t in triaged if t.confirmed]

    md = [
        f"# Cannon report — {target_name}",
        f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}_",
        "",
        "## Salvo",
        f"- **Rounds fired:** {salvo_size if salvo_size is not None else len(rounds)}",
        f"- **Round outcomes:** " + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())),
        f"- **Raw findings:** {raw}  →  **unique:** {len(accumulated)}  →  "
        f"**confirmed:** {len(confirmed)}",
        "",
    ]

    if threat_model is not None:
        graph = threat_model_mermaid(threat_model.components, threat_model.flows, threat_model.boundaries)
        md += ["## Threat model", "", "See [THREAT_MODEL.md](THREAT_MODEL.md).", ""]
        if graph:
            md += [graph, ""]

    md += ["## Triage (ranked)", "", triage_table(triaged), ""]

    if confirmed:
        md += ["## Confirmed findings", ""]
        md += [_confirmed_detail(t) + "\n" for t in confirmed]

    md += ["## Attack chains", "", _chains_section(chains), ""]

    # Provenance appendix — which prompt versions fired.
    md += ["## Appendix — salvo provenance", "",
           "| Round | Status | Focus | Model | find prompt | system prompt |",
           "|---|---|---|---|---|---|"]
    for r in rounds:
        md.append(
            f"| {r.label} | {r.status} | {r.focus_area or '—'} | {r.model} | "
            f"`{r.prompt_shas.get('find','—')}` | `{r.prompt_shas.get('system','—')}` |"
        )
    md.append("")

    out = rd / "REPORT.md"
    out.write_text("\n".join(md))

    if chains:
        (rd / "CHAINS.md").write_text("# Attack chains\n\n" + _chains_section(chains) + "\n")
    return str(out)
