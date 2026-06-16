"""Prompt loader — the mutation surface.

The reference harness buries prompts in .py template strings. cannon makes them
first-class, editable, overridable files so "mutating the prompt to fit a
codebase" is just editing markdown, and every run records which prompt version
(by sha256) produced it.

Resolution order for load_prompt(name, target_dir, variant), highest first:
  1. <target>/prompt_overrides/<name>.md   — per-target shadow
  2. <prompts>/variants/<variant>/<name>.md — a named permutation variant
  3. <prompts>/<name>.md                    — the base template

The sha256 is computed over the RAW template (pre-interpolation), so it
identifies the prompt *version* independent of the target/focus it was filled
with. That's what makes "which prompt produced which findings" answerable.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

# <project_root>/prompts by default; override with CANNON_PROMPTS.
_DEFAULT_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts"


def prompts_dir() -> Path:
    return Path(os.environ.get("CANNON_PROMPTS", _DEFAULT_PROMPTS_DIR))


class _SafeDict(dict):
    """str.format_map helper: leave unknown {placeholders} untouched."""
    def __missing__(self, key):
        return "{" + key + "}"


@dataclass(frozen=True)
class PromptRender:
    name: str
    text: str          # interpolated, ready to send
    sha256: str        # of the raw template — the version id
    source: str        # path the template was loaded from
    variant: str       # which variant was in effect


def resolve_prompt_path(name: str, target_dir: str | None, variant: str) -> Path:
    base = prompts_dir()
    candidates: list[Path] = []
    if target_dir:
        candidates.append(Path(target_dir) / "prompt_overrides" / f"{name}.md")
    if variant and variant != "default":
        candidates.append(base / "variants" / variant / f"{name}.md")
    candidates.append(base / f"{name}.md")
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(
        f"No prompt '{name}' found (looked in: {', '.join(str(c) for c in candidates)})"
    )


def load_prompt(
    name: str,
    *,
    target_dir: str | None = None,
    variant: str = "default",
    vars: dict | None = None,
) -> PromptRender:
    path = resolve_prompt_path(name, target_dir, variant)
    raw = path.read_text()
    sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    text = raw.format_map(_SafeDict(vars or {}))
    return PromptRender(name=name, text=text, sha256=sha, source=str(path), variant=variant)
