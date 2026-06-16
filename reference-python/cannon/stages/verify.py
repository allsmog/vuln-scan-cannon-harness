"""Verify stage — the load-bearing component.

A separate agent, framed as an adversary, re-examines ONE deduped finding
against the source. Findings are guilty until proven innocent: the verifier's
job is to disprove. This is cannon's analogue of the reference harness's
grader; with no executable witness (static review), the witness is an
independent agent that re-reads the cited code path and argues it through.
"""
from __future__ import annotations

import os
import time

from ..agent import AgentResult, parse_xml_tag, run_agent
from ..artifacts import AccumulatedFinding, Verdict
from ..config import TargetConfig
from ..framing import build_system_prompt
from ..prompts import load_prompt

VERIFY_MAX_TURNS = 40


def _parse_confidence(s: str | None) -> float:
    if not s:
        return 0.0
    s = s.strip().rstrip("%")
    try:
        v = float(s)
        return v / 100.0 if v > 1.0 else v
    except ValueError:
        return 0.0


def _norm_verdict(s: str | None) -> str:
    if not s:
        return "UNCERTAIN"
    s = s.strip().upper()
    if s.startswith("REAL") or "TRUE" in s or "CONFIRM" in s:
        return "REAL"
    if "FALSE" in s or s.startswith("FP") or "NOT A" in s or "NOT_A" in s:
        return "FALSE_POSITIVE"
    return "UNCERTAIN"


async def run_verify(
    target: TargetConfig,
    acc: AccumulatedFinding,
    *,
    model: str,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
) -> tuple[Verdict, dict, AgentResult]:
    f = acc.representative
    sys_render = build_system_prompt(target)
    verify_render = load_prompt(
        "verify",
        target_dir=target.target_dir,
        vars={
            "source_root": target.source_root,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": str(f.line) if f.line is not None else "unknown",
            "cwe": f.cwe or "unspecified",
            "description": f.description,
            "evidence": f.evidence,
            "exploit_premise": f.exploit_premise or "(none stated)",
            "corroboration": str(acc.corroboration),
        },
    )

    add_dirs = [target.context_dir] if os.path.isdir(target.context_dir) else None
    result = await run_agent(
        verify_render.text,
        model=model,
        max_turns=VERIFY_MAX_TURNS,
        cwd=target.source_root,
        add_dirs=add_dirs,
        system_prompt=sys_render.text,
        transcript_path=transcript_path,
        progress_prefix=progress_prefix,
    )

    text = result.find_tagged_message("verdict")
    verdict = Verdict(
        signature=acc.signature,
        verdict=_norm_verdict(parse_xml_tag(text, "verdict")),
        confidence=_parse_confidence(parse_xml_tag(text, "confidence")),
        reasoning=parse_xml_tag(text, "reasoning") or "",
    )
    shas = {"system": sys_render.sha256, "verify": verify_render.sha256}
    return verdict, shas, result
