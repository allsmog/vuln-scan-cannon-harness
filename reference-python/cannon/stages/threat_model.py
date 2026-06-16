"""Threat-model stage: read code + context docs, produce a narrative threat
model, a component/data-flow graph (for Mermaid visualization), and a seed set
of focus areas for the cannon.

Aim before you shoot: the reference harness's first move on a large codebase is
to map it. cannon makes that map a first-class, visualizable artifact.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..agent import AgentResult, parse_all_tags, parse_xml_tag, run_agent
from ..config import TargetConfig
from ..framing import build_system_prompt
from ..prompts import load_prompt

THREAT_MODEL_MAX_TURNS = 80


@dataclass
class Component:
    name: str
    description: str = ""
    trust: str = ""   # e.g. "untrusted-input", "trusted-core", "external"


@dataclass
class DataFlow:
    src: str
    dst: str
    label: str = ""


@dataclass
class ThreatModel:
    narrative: str = ""
    components: list[Component] = field(default_factory=list)
    flows: list[DataFlow] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "narrative": self.narrative,
            "components": [c.__dict__ for c in self.components],
            "flows": [f.__dict__ for f in self.flows],
            "boundaries": self.boundaries,
            "focus_areas": self.focus_areas,
        }


def _parse_components(text: str) -> list[Component]:
    out = []
    for block in parse_all_tags(text, "component"):
        # format: name | trust | description   (pipe-separated, trailing optional)
        parts = [p.strip() for p in block.split("|")]
        if not parts or not parts[0]:
            continue
        out.append(Component(
            name=parts[0],
            trust=parts[1] if len(parts) > 1 else "",
            description=parts[2] if len(parts) > 2 else "",
        ))
    return out


def _parse_flows(text: str) -> list[DataFlow]:
    out = []
    for block in parse_all_tags(text, "data_flow"):
        # format: src -> dst : label
        label = ""
        body = block
        if ":" in block:
            body, label = block.split(":", 1)
        if "->" not in body:
            continue
        src, dst = body.split("->", 1)
        out.append(DataFlow(src=src.strip(), dst=dst.strip(), label=label.strip()))
    return out


async def run_threat_model(
    target: TargetConfig,
    *,
    model: str,
    context_block: str = "",
    transcript_path: str | None = None,
    progress_prefix: str | None = "[threat]",
) -> tuple[ThreatModel, dict, AgentResult]:
    sys_render = build_system_prompt(target)
    tm_render = load_prompt(
        "threat_model",
        target_dir=target.target_dir,
        vars={
            "source_root": target.source_root,
            "language": target.language or "unspecified",
            "description": target.description or "(no description provided)",
            "context": context_block or "(no project context documents were provided)",
        },
    )
    add_dirs = [target.context_dir] if os.path.isdir(target.context_dir) else None
    result = await run_agent(
        tm_render.text,
        model=model,
        max_turns=THREAT_MODEL_MAX_TURNS,
        cwd=target.source_root,
        add_dirs=add_dirs,
        system_prompt=sys_render.text,
        transcript_path=transcript_path,
        progress_prefix=progress_prefix,
    )
    text = result.all_text()
    narrative = parse_xml_tag(text, "threat_model") or ""
    focus_raw = parse_xml_tag(text, "focus_areas")
    focus = [ln.strip(" -\t") for ln in focus_raw.splitlines() if ln.strip(" -\t")] if focus_raw else []
    boundaries = [b for b in (parse_xml_tag(text, "trust_boundary") or "").splitlines() if b.strip()]

    tm = ThreatModel(
        narrative=narrative,
        components=_parse_components(text),
        flows=_parse_flows(text),
        boundaries=boundaries,
        focus_areas=focus,
    )
    return tm, {"system": sys_render.sha256, "threat_model": tm_render.sha256}, result
