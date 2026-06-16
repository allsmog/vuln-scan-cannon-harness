"""Attack-chain stage: take the CONFIRMED findings and have an agent compose
multi-step attack chains — how individual primitives combine into real impact.
The reference harness calls these 'bug chains'; cannon emits them as structured
Chain objects that render to a Mermaid graph.
"""
from __future__ import annotations

import os

from ..agent import AgentResult, parse_all_tags, parse_xml_tag, run_agent
from ..artifacts import Chain, ChainStep, TriagedFinding, norm_severity
from ..config import TargetConfig
from ..framing import build_system_prompt
from ..prompts import load_prompt

CHAIN_MAX_TURNS = 60


def _catalog(confirmed: list[TriagedFinding]) -> str:
    lines = []
    for t in confirmed:
        f = t.accumulated.representative
        loc = f.file + (f":{f.line}" if f.line else "")
        lines.append(
            f"- [{t.accumulated.signature}] {f.severity} {f.title} @ {loc}\n"
            f"    premise: {f.exploit_premise or '(none stated)'}\n"
            f"    what it gives the attacker: {f.description[:240]}"
        )
    return "\n".join(lines)


def _title_by_sig(confirmed: list[TriagedFinding]) -> dict[str, str]:
    return {t.accumulated.signature: t.accumulated.representative.title for t in confirmed}


def _parse_chain_block(block: str, sig_titles: dict[str, str]) -> Chain | None:
    title = parse_xml_tag(block, "title")
    if not title:
        return None
    steps: list[ChainStep] = []
    for raw in parse_all_tags(block, "step"):
        sig, action = (raw.split("|", 1) + [""])[:2] if "|" in raw else ("", raw)
        sig = sig.strip().strip("[]")   # agents often copy the bracketed [sig] literally
        steps.append(ChainStep(
            signature=sig if sig and sig != "-" else "",
            title=sig_titles.get(sig, ""),
            action=action.strip(),
        ))
    return Chain(
        title=title,
        premise=parse_xml_tag(block, "premise") or "",
        steps=steps,
        impact=parse_xml_tag(block, "impact") or "",
        severity=norm_severity(parse_xml_tag(block, "severity")),
    )


async def run_chain(
    target: TargetConfig,
    confirmed: list[TriagedFinding],
    *,
    model: str,
    context_block: str = "",
    transcript_path: str | None = None,
    progress_prefix: str | None = "[chain]",
) -> tuple[list[Chain], dict, AgentResult]:
    if not confirmed:
        return [], {}, AgentResult()

    sys_render = build_system_prompt(target)
    chain_render = load_prompt(
        "chain",
        target_dir=target.target_dir,
        vars={
            "source_root": target.source_root,
            "findings_catalog": _catalog(confirmed),
            "context": context_block or "(no project context documents were provided)",
        },
    )
    add_dirs = [target.context_dir] if os.path.isdir(target.context_dir) else None
    result = await run_agent(
        chain_render.text,
        model=model,
        max_turns=CHAIN_MAX_TURNS,
        cwd=target.source_root,
        add_dirs=add_dirs,
        system_prompt=sys_render.text,
        transcript_path=transcript_path,
        progress_prefix=progress_prefix,
    )

    sig_titles = _title_by_sig(confirmed)
    chains: list[Chain] = []
    for block in parse_all_tags(result.all_text(), "chain"):
        c = _parse_chain_block(block, sig_titles)
        if c:
            chains.append(c)
    return chains, {"system": sys_render.sha256, "chain": chain_render.sha256}, result
