"""Recon stage: partition the target's attack surface into focus areas so the
salvo's parallel rounds start in different places instead of converging on the
same shallow bug. Emits a <focus_areas> block, one area per line.
"""
from __future__ import annotations

import os

from ..agent import AgentResult, parse_xml_tag, run_agent
from ..config import TargetConfig
from ..framing import build_system_prompt
from ..prompts import load_prompt

RECON_MAX_TURNS = 60


async def run_recon(
    target: TargetConfig,
    *,
    model: str,
    context_block: str = "",
    transcript_path: str | None = None,
    progress_prefix: str | None = "[recon]",
) -> tuple[list[str], dict, AgentResult]:
    sys_render = build_system_prompt(target)
    recon_render = load_prompt(
        "recon",
        target_dir=target.target_dir,
        vars={
            "source_root": target.source_root,
            "language": target.language or "unspecified",
            "context": context_block or "(no project context documents were provided)",
        },
    )
    add_dirs = [target.context_dir] if os.path.isdir(target.context_dir) else None
    result = await run_agent(
        recon_render.text,
        model=model,
        max_turns=RECON_MAX_TURNS,
        cwd=target.source_root,
        add_dirs=add_dirs,
        system_prompt=sys_render.text,
        transcript_path=transcript_path,
        progress_prefix=progress_prefix,
    )
    raw = parse_xml_tag(result.find_tagged_message("focus_areas"), "focus_areas")
    areas = [ln.strip(" -\t") for ln in raw.splitlines() if ln.strip(" -\t")] if raw else []
    return areas, {"system": sys_render.sha256, "recon": recon_render.sha256}, result
