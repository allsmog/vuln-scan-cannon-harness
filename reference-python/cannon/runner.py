"""run_salvo — the ONLY orchestration seam.

This is the entire 'run-management system': a bounded asyncio fan-out over the
permutation matrix, each round checkpointed to its own run_NNN/result.json, with
--resume skipping terminal rounds. No broker, no DB. The day you genuinely need
to distribute rounds across machines, you replace the body of this one function
with a producer/consumer — every stage above and below it stays unchanged.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from .agent import color
from .artifacts import RoundResult, TERMINAL_STATUSES
from .permute import Spec


def round_dir(results_dir: str, idx: int) -> str:
    return os.path.join(results_dir, f"run_{idx:03d}")


def load_rounds(results_dir: str) -> list[RoundResult]:
    """Read every run_*/result.json under a results dir, in order."""
    root = Path(results_dir)
    out: list[RoundResult] = []
    for d in sorted(root.glob("run_*")):
        ckpt = d / "result.json"
        if ckpt.is_file():
            try:
                out.append(RoundResult.from_json(ckpt.read_text()))
            except Exception as e:
                print(f"[warn] unreadable checkpoint {ckpt}: {e}", file=sys.stderr)
    return out


async def run_salvo(
    specs: list[Spec],
    *,
    results_dir: str,
    detector_fn,
    context_block: str,
    concurrency: int,
    resume: bool = False,
) -> list[RoundResult]:
    os.makedirs(results_dir, exist_ok=True)
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[RoundResult | None] = [None] * len(specs)

    skipped = 0

    async def _task(i: int, spec: Spec) -> None:
        nonlocal skipped
        out_dir = round_dir(results_dir, spec.round_idx)
        ckpt = Path(out_dir) / "result.json"

        if resume and ckpt.is_file():
            try:
                prev = RoundResult.from_json(ckpt.read_text())
                if prev.status in TERMINAL_STATUSES and prev.status != "agent_failed":
                    results[i] = prev
                    skipped += 1
                    return
            except Exception:
                pass  # corrupt checkpoint → re-run

        async with sem:
            print(color(f"  ▸ firing {spec.label}  "
                        f"[{spec.focus_area or 'no focus'} · {spec.model}]", "cannon"))
            try:
                rr = await detector_fn(
                    spec, context_block=context_block, out_dir=out_dir,
                    progress_prefix=f"  [{spec.label}]",
                )
            except Exception as e:
                rr = RoundResult(
                    target=spec.target.name, label=spec.label, status="error",
                    focus_area=spec.focus_area, variant=spec.variant, model=spec.model,
                    error=f"{type(e).__name__}: {e}",
                )

        os.makedirs(out_dir, exist_ok=True)
        # Atomic-ish checkpoint write.
        tmp = ckpt.with_suffix(".json.tmp")
        tmp.write_text(rr.to_json())
        os.replace(tmp, ckpt)

        nf = len(rr.findings)
        tag = color(f"{nf} finding(s)", "bold") if nf else "no findings"
        status_col = "red" if rr.status in ("error", "agent_failed") else "report"
        print(color(f"  ✓ {spec.label}: {rr.status} — {tag}", status_col))
        results[i] = rr

    await asyncio.gather(*[_task(i, s) for i, s in enumerate(specs)])

    if skipped:
        print(color(f"  [resume] skipped {skipped} already-terminal round(s)", "dim"))
    return [r for r in results if r is not None]
