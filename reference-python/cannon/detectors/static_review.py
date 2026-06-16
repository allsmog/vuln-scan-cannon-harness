"""static_review detector — the first instantiation.

Turns one Spec into one RoundResult by running the find stage (read-only,
no execution). The matching verifier is the shared adversarial reviewer in
stages/verify.py (no executable witness needed for static review).

A future `dynamic` detector would implement the same run_round() signature but
build/run the target in a sandbox and emit a PoC witness — the runner and
triage code above it don't change.
"""
from __future__ import annotations

import os

from ..artifacts import RoundResult
from ..permute import Spec
from ..stages.find import run_find

DETECTOR_NAME = "static_review"


async def run_round(
    spec: Spec,
    *,
    context_block: str,
    out_dir: str,
    progress_prefix: str | None = None,
) -> RoundResult:
    os.makedirs(out_dir, exist_ok=True)
    transcript_path = os.path.join(out_dir, "find_transcript.jsonl")

    findings, shas, sources, agent_result, elapsed = await run_find(
        spec,
        context_block=context_block,
        transcript_path=transcript_path,
        progress_prefix=progress_prefix,
    )

    if agent_result.error:
        status = "agent_failed"
    elif findings:
        status = "completed"
    else:
        status = "no_findings"

    return RoundResult(
        target=spec.target.name,
        label=spec.label,
        status=status,
        focus_area=spec.focus_area,
        variant=spec.variant,
        model=spec.model,
        findings=findings,
        prompt_shas=shas,
        prompt_sources=sources,
        timings={"find": round(elapsed, 1)},
        session_id=agent_result.session_id,
        error=agent_result.error,
    )


# Detector registry — name → run_round callable.
DETECTORS = {DETECTOR_NAME: run_round}
