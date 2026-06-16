"""Find stage: one find-agent reads the target source (scoped by focus area)
and emits structured <finding> blocks. No execution — read-only tools.
"""
from __future__ import annotations

import os
import time

from ..agent import AgentResult, parse_all_tags, parse_xml_tag, run_agent
from ..artifacts import Finding, norm_severity
from ..framing import build_system_prompt
from ..permute import Spec
from ..prompts import load_prompt

FIND_MAX_TURNS = 120


def _parse_line(s: str | None) -> int | None:
    if not s:
        return None
    m = "".join(ch for ch in s if ch.isdigit())
    return int(m) if m else None


def _parse_finding_block(block: str, spec: Spec) -> Finding | None:
    title = parse_xml_tag(block, "title")
    file = parse_xml_tag(block, "file")
    if not title or not file:
        return None
    return Finding(
        title=title,
        severity=norm_severity(parse_xml_tag(block, "severity")),
        file=file,
        line=_parse_line(parse_xml_tag(block, "line")),
        cwe=parse_xml_tag(block, "cwe"),
        description=parse_xml_tag(block, "description") or "",
        evidence=parse_xml_tag(block, "evidence") or "",
        exploit_premise=parse_xml_tag(block, "exploit_premise") or "",
        focus_area=spec.focus_area,
        round_label=spec.label,
    )


async def run_find(
    spec: Spec,
    *,
    context_block: str,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    max_turns: int = FIND_MAX_TURNS,
) -> tuple[list[Finding], dict, dict, AgentResult, float]:
    """Returns (findings, prompt_shas, prompt_sources, agent_result, elapsed)."""
    target = spec.target
    sys_render = build_system_prompt(target, spec.variant)
    find_render = load_prompt(
        "find",
        target_dir=target.target_dir,
        variant=spec.variant,
        vars={
            "source_root": target.source_root,
            "language": target.language or "unspecified",
            "focus_area": spec.focus_area or "the entire codebase (no specific focus area assigned)",
            "context": context_block or "(no project context documents were provided)",
        },
    )

    add_dirs = [target.context_dir] if os.path.isdir(target.context_dir) else None
    t0 = time.time()
    result = await run_agent(
        find_render.text,
        model=spec.model,
        max_turns=max_turns,
        cwd=target.source_root,
        add_dirs=add_dirs,
        system_prompt=sys_render.text,
        transcript_path=transcript_path,
        progress_prefix=progress_prefix,
    )
    elapsed = time.time() - t0

    findings: list[Finding] = []
    for block in parse_all_tags(result.all_text(), "finding"):
        f = _parse_finding_block(block, spec)
        if f:
            findings.append(f)

    shas = {"system": sys_render.sha256, "find": find_render.sha256}
    sources = {"system": sys_render.source, "find": find_render.source}
    return findings, shas, sources, result, elapsed
