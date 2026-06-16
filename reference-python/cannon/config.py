"""Target configuration loader.

A target is a directory under targets/ containing:
  - config.yaml          (metadata cannon needs)
  - src/ (or source_root) the code to scan
  - context/             (optional design docs, threat notes — auto-injected)
  - prompt_overrides/    (optional per-target prompt files that shadow ../../prompts)

Adding a new target = new dir, zero pipeline code changes (the reference's
principle, ported).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class TargetConfig:
    name: str
    target_dir: str          # the targets/<name>/ dir
    source_root: str         # absolute path to the code to scan
    detector: str = "static_review"
    language: str | None = None
    description: str | None = None
    focus_areas: list[str] = field(default_factory=list)
    engagement_context: str | None = None   # inline authorization block (or path)

    @property
    def context_dir(self) -> str:
        return str(Path(self.target_dir) / "context")

    @property
    def prompt_overrides_dir(self) -> str:
        return str(Path(self.target_dir) / "prompt_overrides")

    @classmethod
    def load(cls, target: str | Path, targets_root: str | Path | None = None) -> "TargetConfig":
        """Load a target by name (resolved under targets_root) or by path."""
        p = Path(target)
        if not p.exists() and targets_root is not None:
            p = Path(targets_root) / target
        p = p.resolve()
        config_path = p / "config.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"No config.yaml in {p}")

        cfg = yaml.safe_load(config_path.read_text()) or {}

        # source_root: absolute as-is, else relative to the target dir; default
        # to src/ if present, otherwise the target dir itself.
        sr = cfg.get("source_root")
        if sr:
            source_root = Path(sr)
            if not source_root.is_absolute():
                source_root = p / source_root
        elif (p / "src").is_dir():
            source_root = p / "src"
        else:
            source_root = p
        source_root = source_root.resolve()

        # engagement_context may be inline text or a path relative to the target.
        eng = cfg.get("engagement_context")
        if eng and "\n" not in eng and (p / eng).exists():
            eng = (p / eng).read_text().strip()

        return cls(
            name=p.name,
            target_dir=str(p),
            source_root=str(source_root),
            detector=cfg.get("detector", "static_review"),
            language=cfg.get("language"),
            description=cfg.get("description"),
            focus_areas=cfg.get("focus_areas") or [],
            engagement_context=eng,
        )
