"""System-prompt construction, shared by every stage agent.

Two layers, mirroring the reference harness:
  - prompts/system.md  : the always-true framing (read-only, evidence rules)
  - engagement context : who authorized the work / where findings go,
                         overridable per target via config.yaml's
                         `engagement_context` (inline or a file path).
"""
from __future__ import annotations

from .config import TargetConfig
from .prompts import PromptRender, load_prompt

DEFAULT_ENGAGEMENT = (
    "This is authorized defensive security research: a static source-code "
    "review of a codebase the operator owns or is permitted to assess. "
    "Findings are collected for remediation. You only read source — you never "
    "execute the target."
)


def build_system_prompt(target: TargetConfig, variant: str = "default") -> PromptRender:
    """Render prompts/system.md with the engagement block interpolated."""
    return load_prompt(
        "system",
        target_dir=target.target_dir,
        variant=variant,
        vars={
            "engagement": target.engagement_context or DEFAULT_ENGAGEMENT,
            "language": target.language or "unspecified",
        },
    )
