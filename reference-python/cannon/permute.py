"""The permutation matrix — the 'cannon' part.

One target, fired at from many angles. A salvo is the cross product of:
    focus areas × prompt variants × models × repeats

Each cell is one Spec → one find→verify round → one run_NNN/result.json
checkpoint. Unioning their findings (see artifacts.accumulate) turns variance
into coverage: the reference harness's 'run several, union the results, don't
trust any single pass' — as a deliberate matrix instead of a hope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .config import TargetConfig


@dataclass(frozen=True)
class Spec:
    target: TargetConfig
    round_idx: int
    label: str
    focus_area: str | None
    variant: str
    model: str


def _slug(s: str, n: int = 18) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return s[:n] or "all"


def _short_model(m: str) -> str:
    # "claude-opus-4-8" -> "opus", "sonnet" -> "sonnet"
    for tag in ("opus", "sonnet", "haiku"):
        if tag in m:
            return tag
    return _slug(m, 10)


def build_matrix(
    target: TargetConfig,
    *,
    focus_areas: list[str] | None,
    variants: list[str],
    models: list[str],
    runs: int,
) -> list[Spec]:
    """Build the salvo. focus_areas=None/[] means one un-focused round per cell."""
    focuses: list[str | None] = list(focus_areas) if focus_areas else [None]
    specs: list[Spec] = []
    idx = 0
    for model in models:
        for variant in variants:
            for focus in focuses:
                for _ in range(runs):
                    parts = [f"r{idx:02d}"]
                    if focus:
                        parts.append(_slug(focus))
                    if variant != "default":
                        parts.append(f"v={_slug(variant, 10)}")
                    if len(models) > 1:
                        parts.append(_short_model(model))
                    label = "·".join(parts)
                    specs.append(Spec(
                        target=target, round_idx=idx, label=label,
                        focus_area=focus, variant=variant, model=model,
                    ))
                    idx += 1
    return specs
