"""Data contracts for the cannon pipeline.

Flow of artifacts:
  Finding         — one issue claimed by one find-agent (one round)
  RoundResult     — one salvo round's outcome (checkpoint of record on disk)
  AccumulatedFinding — Findings unioned + deduped across all rounds (corroboration)
  Verdict         — the adversarial verifier's call on a deduped finding
  TriagedFinding  — accumulated + verdict + rank score
  Chain           — a multi-step attack composed from confirmed findings
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_WEIGHT = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.5}

# Terminal round statuses (used by --resume to skip finished work).
TERMINAL_STATUSES = {"completed", "no_findings", "agent_failed", "error"}


def norm_severity(s: str | None) -> str:
    if not s:
        return "INFO"
    s = s.strip().upper()
    for sev in SEVERITIES:
        if s.startswith(sev):
            return sev
    return "INFO"


def sev_rank(s: str) -> int:
    """Higher = more severe. For sorting."""
    return len(SEVERITIES) - SEVERITIES.index(norm_severity(s))


# ──────────────────────────────────────────────────────────────────────────────
# Finding (per round)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title: str
    severity: str
    file: str
    line: int | None = None
    cwe: str | None = None
    description: str = ""
    evidence: str = ""
    exploit_premise: str = ""
    focus_area: str | None = None
    round_label: str | None = None

    def signature(self) -> str:
        """Stable identity for cross-round dedup: (basename, line-bucket, class).

        Line is bucketed by 10 so near-identical reports of the same bug collapse;
        class is the CWE if present, else a normalized title."""
        base = Path(self.file or "?").name
        bucket = (self.line // 10) if isinstance(self.line, int) else -1
        if self.cwe:
            cls = re.sub(r"[^0-9]", "", self.cwe) or self.cwe.strip().lower()
        else:
            cls = re.sub(r"[^a-z0-9]+", "-", (self.title or "").lower()).strip("-")[:40]
        return f"{base}:{bucket}:{cls}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            title=d.get("title", "untitled"),
            severity=norm_severity(d.get("severity")),
            file=d.get("file", "?"),
            line=d.get("line"),
            cwe=d.get("cwe"),
            description=d.get("description", ""),
            evidence=d.get("evidence", ""),
            exploit_premise=d.get("exploit_premise", ""),
            focus_area=d.get("focus_area"),
            round_label=d.get("round_label"),
        )


# ──────────────────────────────────────────────────────────────────────────────
# RoundResult (per salvo round — the on-disk checkpoint)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RoundResult:
    target: str
    label: str                       # human id, e.g. "f02·variant=default·png-parser"
    status: str                      # completed | no_findings | agent_failed | error
    focus_area: str | None = None
    variant: str = "default"
    model: str = ""
    findings: list[Finding] = field(default_factory=list)
    prompt_shas: dict[str, str] = field(default_factory=dict)   # stage -> sha
    prompt_sources: dict[str, str] = field(default_factory=dict)
    timings: dict[str, float] = field(default_factory=dict)
    session_id: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RoundResult":
        return cls(
            target=d["target"],
            label=d["label"],
            status=d["status"],
            focus_area=d.get("focus_area"),
            variant=d.get("variant", "default"),
            model=d.get("model", ""),
            findings=[Finding.from_dict(x) for x in d.get("findings", [])],
            prompt_shas=d.get("prompt_shas", {}),
            prompt_sources=d.get("prompt_sources", {}),
            timings=d.get("timings", {}),
            session_id=d.get("session_id"),
            error=d.get("error"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, s: str) -> "RoundResult":
        return cls.from_dict(json.loads(s))


# ──────────────────────────────────────────────────────────────────────────────
# Accumulation (union + dedup across rounds)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AccumulatedFinding:
    signature: str
    representative: Finding           # the highest-severity instance
    corroboration: int                # how many rounds independently reported it
    rounds: list[str]                 # round labels that reported it
    max_severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "representative": self.representative.to_dict(),
            "corroboration": self.corroboration,
            "rounds": self.rounds,
            "max_severity": self.max_severity,
        }


def accumulate(rounds: list[RoundResult]) -> list[AccumulatedFinding]:
    """Union every round's findings, collapse by signature, count corroboration.

    Cross-run corroboration is signal: a bug found by independent rounds is more
    likely real (the reference's 'expect variance; union across runs')."""
    buckets: dict[str, list[Finding]] = {}
    labels: dict[str, list[str]] = {}
    for r in rounds:
        for f in r.findings:
            sig = f.signature()
            buckets.setdefault(sig, []).append(f)
            labels.setdefault(sig, [])
            if r.label not in labels[sig]:
                labels[sig].append(r.label)

    out: list[AccumulatedFinding] = []
    for sig, items in buckets.items():
        rep = max(items, key=lambda f: (sev_rank(f.severity), len(f.evidence)))
        max_sev = max((f.severity for f in items), key=sev_rank)
        out.append(AccumulatedFinding(
            signature=sig,
            representative=rep,
            corroboration=len(labels[sig]),
            rounds=labels[sig],
            max_severity=max_sev,
        ))
    out.sort(key=lambda a: (sev_rank(a.max_severity), a.corroboration), reverse=True)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Triage (adversarial verdict + ranking)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    signature: str
    verdict: str          # REAL | FALSE_POSITIVE | UNCERTAIN
    confidence: float     # 0.0–1.0
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Verdict":
        return cls(d["signature"], d["verdict"], d.get("confidence", 0.0), d.get("reasoning", ""))


@dataclass
class TriagedFinding:
    accumulated: AccumulatedFinding
    verdict: Verdict
    rank_score: float

    @property
    def confirmed(self) -> bool:
        return self.verdict.verdict == "REAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank_score": round(self.rank_score, 3),
            "confirmed": self.confirmed,
            "verdict": self.verdict.to_dict(),
            **self.accumulated.to_dict(),
        }


def rank(accumulated: AccumulatedFinding, verdict: Verdict) -> float:
    """severity × confidence × corroboration boost. Corroboration adds 50%/extra round."""
    weight = _SEV_WEIGHT.get(norm_severity(accumulated.max_severity), 0.5)
    corro_boost = 1.0 + 0.5 * (accumulated.corroboration - 1)
    return weight * max(verdict.confidence, 0.0) * corro_boost


def triage(accumulated: list[AccumulatedFinding], verdicts: dict[str, Verdict]) -> list[TriagedFinding]:
    out: list[TriagedFinding] = []
    for a in accumulated:
        v = verdicts.get(a.signature, Verdict(a.signature, "UNCERTAIN", 0.3, "no verdict"))
        out.append(TriagedFinding(accumulated=a, verdict=v, rank_score=rank(a, v)))
    # Confirmed first, then by rank score.
    out.sort(key=lambda t: (t.confirmed, t.rank_score), reverse=True)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Attack chains
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    signature: str        # which finding this step uses ("" for a non-finding link)
    title: str
    action: str           # what the attacker does at this step

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ChainStep":
        return cls(d.get("signature", ""), d.get("title", ""), d.get("action", ""))


@dataclass
class Chain:
    title: str
    premise: str          # attacker's starting position / preconditions
    steps: list[ChainStep]
    impact: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["steps"] = [s.to_dict() for s in self.steps]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Chain":
        return cls(
            title=d.get("title", "chain"),
            premise=d.get("premise", ""),
            steps=[ChainStep.from_dict(x) for x in d.get("steps", [])],
            impact=d.get("impact", ""),
            severity=norm_severity(d.get("severity")),
        )
