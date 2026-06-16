"""cannon — CLI entrypoint.

  cannon fire <target> [--runs N] [--concurrency K] [--threat-model] [--chain]
                       [--focus "a;b"] [--variants v1,v2] [--models m1,m2]
                       [--resume <results_dir>]
        Fire a salvo of permuted scans, accumulate, triage, (chain), report.

  cannon recon <target>             Print a focus-area partition.
  cannon threat-model <target>      Build THREAT_MODEL.md + Mermaid graph.
  cannon triage <results_dir>       Re-accumulate + adversarially verify + report.
  cannon chain  <results_dir>       Compose attack chains from confirmed findings.
  cannon report <results_dir>       Re-render REPORT.md from existing artifacts.

Targets live under ./targets/<name>/ (config.yaml + src/ + optional context/).
Results land in ./results/<target>/<timestamp>/.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from .agent import color
from .artifacts import accumulate, triage as triage_fn, Verdict
from .config import TargetConfig
from .context import load_context
from .detectors.static_review import DETECTORS
from .permute import Spec, build_matrix
from .runner import load_rounds, run_salvo

DEFAULT_MODEL = os.environ.get("CANNON_MODEL", "opus")
TARGETS_ROOT = os.environ.get("CANNON_TARGETS", "targets")
RESULTS_ROOT = os.environ.get("CANNON_RESULTS", "results")


# ──────────────────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────────────────

def _safe(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)[:60]


def _new_results_dir(target_name: str) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    d = os.path.join(RESULTS_ROOT, target_name, ts)
    os.makedirs(d, exist_ok=True)
    return d


def _csv(s: str | None) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()] if s else []


def _detector_for(target: TargetConfig):
    fn = DETECTORS.get(target.detector)
    if not fn:
        sys.exit(f"error: unknown detector '{target.detector}' "
                 f"(have: {', '.join(DETECTORS)})")
    return fn


def _save_manifest(results_dir: str, specs: list[Spec]) -> None:
    manifest = [
        {"round_idx": s.round_idx, "label": s.label, "focus_area": s.focus_area,
         "variant": s.variant, "model": s.model}
        for s in specs
    ]
    Path(results_dir, "salvo.json").write_text(json.dumps(manifest, indent=2))


def _load_manifest(results_dir: str, target: TargetConfig) -> list[Spec]:
    raw = json.loads(Path(results_dir, "salvo.json").read_text())
    return [Spec(target=target, round_idx=m["round_idx"], label=m["label"],
                 focus_area=m.get("focus_area"), variant=m.get("variant", "default"),
                 model=m.get("model", DEFAULT_MODEL)) for m in raw]


def _banner(target: TargetConfig, n_specs: int, focuses, variants, models) -> None:
    print(color("\n  ╔══════════════════════════════════════════╗", "cannon"))
    print(color("  ║   V U L N - S C A N   C A N N O N         ║", "cannon"))
    print(color("  ╚══════════════════════════════════════════╝", "cannon"))
    print(f"  target   : {color(target.name, 'bold')}  ({target.detector})")
    print(f"  source   : {target.source_root}")
    print(f"  salvo    : {color(str(n_specs), 'bold')} rounds  "
          f"= {len(focuses)} focus × {len(variants)} variant × {len(models)} model × runs")
    print(f"  focuses  : {', '.join(f or 'none' for f in focuses)}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# triage (verify-all) — shared by `fire` and `triage`
# ──────────────────────────────────────────────────────────────────────────────

async def _verify_all(target, accumulated, *, model, results_dir, concurrency, top):
    from .stages.verify import run_verify
    verify_dir = os.path.join(results_dir, "verify")
    os.makedirs(verify_dir, exist_ok=True)
    items = accumulated[:top] if top and top > 0 else accumulated
    sem = asyncio.Semaphore(max(1, concurrency))
    verdicts: dict[str, Verdict] = {}

    async def _one(acc):
        async with sem:
            print(color(f"  ⚖ verifying {acc.max_severity} {acc.representative.title[:60]} "
                        f"(×{acc.corroboration})", "verify"))
            tp = os.path.join(verify_dir, f"{_safe(acc.signature)}.jsonl")
            try:
                verdict, _shas, _res = await run_verify(
                    target, acc, model=model, transcript_path=tp,
                    progress_prefix=f"  [verify {acc.signature[:18]}]")
            except Exception as e:
                verdict = Verdict(acc.signature, "UNCERTAIN", 0.0, f"verify error: {e}")
            verdicts[acc.signature] = verdict
            mark = {"REAL": "✅", "FALSE_POSITIVE": "❌"}.get(verdict.verdict, "❔")
            print(f"    {mark} {verdict.verdict} ({verdict.confidence:.2f})")

    await asyncio.gather(*[_one(a) for a in items])
    return verdicts


# ──────────────────────────────────────────────────────────────────────────────
# commands
# ──────────────────────────────────────────────────────────────────────────────

async def cmd_fire(args) -> None:
    target = TargetConfig.load(args.target, TARGETS_ROOT)
    detector_fn = _detector_for(target)
    context_block, ctx_files = load_context(target.context_dir)
    if ctx_files:
        print(color(f"  context: fed {len(ctx_files)} doc(s) from context/", "dim"))

    models = _csv(args.models) or [args.model]
    variants = _csv(args.variants) or ["default"]

    # ---- resume path: rebuild the exact matrix from salvo.json ----
    if args.resume:
        results_dir = args.resume
        specs = _load_manifest(results_dir, target)
        threat_model = None
        tmj = Path(results_dir, "threat_model.json")
        focuses = sorted({s.focus_area for s in specs}, key=lambda x: (x is None, x))
    else:
        results_dir = _new_results_dir(target.name)
        # ---- focus resolution ----
        threat_model = None
        if args.threat_model:
            from .stages.threat_model import run_threat_model
            from .stages.report import write_threat_model
            print(color("  ◆ threat-modeling…", "threat"))
            threat_model, _shas, _res = await run_threat_model(
                target, model=args.model, context_block=context_block,
                transcript_path=os.path.join(results_dir, "threat_model_transcript.jsonl"))
            write_threat_model(results_dir, threat_model)
            print(color(f"    → {len(threat_model.components)} components, "
                        f"{len(threat_model.focus_areas)} focus areas → THREAT_MODEL.md", "threat"))
            focus_areas = threat_model.focus_areas
        elif args.recon:
            from .stages.recon import run_recon
            print(color("  ◆ recon…", "recon"))
            focus_areas, _shas, _res = await run_recon(
                target, model=args.model, context_block=context_block,
                transcript_path=os.path.join(results_dir, "recon_transcript.jsonl"))
        elif args.focus:
            focus_areas = [x.strip() for x in args.focus.split(";") if x.strip()]
        else:
            focus_areas = target.focus_areas

        specs = build_matrix(target, focus_areas=focus_areas, variants=variants,
                             models=models, runs=args.runs)
        focuses = focus_areas or [None]
        _save_manifest(results_dir, specs)

    _banner(target, len(specs), focuses, variants, models)

    # ---- the salvo ----
    rounds = await run_salvo(
        specs, results_dir=results_dir, detector_fn=detector_fn,
        context_block=context_block, concurrency=args.concurrency, resume=bool(args.resume))

    # ---- accumulate → triage ----
    accumulated = accumulate(rounds)
    print(color(f"\n  ⊕ accumulated {sum(len(r.findings) for r in rounds)} raw → "
                f"{len(accumulated)} unique findings", "bold"))
    verdicts = await _verify_all(target, accumulated, model=args.model,
                                 results_dir=results_dir, concurrency=args.concurrency,
                                 top=args.verify_top)
    triaged = triage_fn(accumulated, verdicts)
    confirmed = [t for t in triaged if t.confirmed]

    # ---- chains ----
    chains = []
    if args.chain and confirmed:
        from .stages.chain import run_chain
        print(color(f"\n  ⛓ chaining {len(confirmed)} confirmed finding(s)…", "chain"))
        chains, _shas, _res = await run_chain(
            target, confirmed, model=args.model, context_block=context_block,
            transcript_path=os.path.join(results_dir, "chain_transcript.jsonl"))
        print(color(f"    → {len(chains)} chain(s)", "chain"))

    # ---- report ----
    _render(results_dir, target.name, rounds, accumulated, triaged, chains,
            threat_model, salvo_size=len(specs))
    _final_summary(results_dir, triaged, chains)


async def cmd_recon(args) -> None:
    from .stages.recon import run_recon
    target = TargetConfig.load(args.target, TARGETS_ROOT)
    context_block, _ = load_context(target.context_dir)
    areas, _shas, _res = await run_recon(target, model=args.model, context_block=context_block)
    print(color(f"\n  focus areas for {target.name}:", "bold"))
    for a in areas:
        print(f"  - {a}")


async def cmd_threat_model(args) -> None:
    from .stages.threat_model import run_threat_model
    from .stages.report import write_threat_model
    target = TargetConfig.load(args.target, TARGETS_ROOT)
    context_block, _ = load_context(target.context_dir)
    results_dir = _new_results_dir(target.name)
    tm, _shas, _res = await run_threat_model(
        target, model=args.model, context_block=context_block,
        transcript_path=os.path.join(results_dir, "threat_model_transcript.jsonl"))
    path = write_threat_model(results_dir, tm)
    print(color(f"\n  → {path}", "bold"))
    print(f"  components: {len(tm.components)}  flows: {len(tm.flows)}  "
          f"focus areas: {len(tm.focus_areas)}")


async def cmd_triage(args) -> None:
    target = TargetConfig.load(_target_from_results(args.results_dir), TARGETS_ROOT)
    rounds = load_rounds(args.results_dir)
    if not rounds:
        sys.exit(f"error: no run_*/result.json under {args.results_dir}")
    accumulated = accumulate(rounds)
    print(color(f"  ⊕ {len(accumulated)} unique findings from {len(rounds)} rounds", "bold"))
    verdicts = await _verify_all(target, accumulated, model=args.model,
                                 results_dir=args.results_dir, concurrency=args.concurrency,
                                 top=args.verify_top)
    triaged = triage_fn(accumulated, verdicts)
    _render(args.results_dir, target.name, rounds, accumulated, triaged, [], None)
    _final_summary(args.results_dir, triaged, [])


async def cmd_chain(args) -> None:
    from .stages.chain import run_chain
    target = TargetConfig.load(_target_from_results(args.results_dir), TARGETS_ROOT)
    context_block, _ = load_context(target.context_dir)
    rounds = load_rounds(args.results_dir)
    accumulated = accumulate(rounds)
    # Reuse existing verdicts if present, else everything is unverified.
    verdicts = _load_verdicts(args.results_dir)
    triaged = triage_fn(accumulated, verdicts)
    confirmed = [t for t in triaged if t.confirmed] or triaged  # fall back to all if none verified
    chains, _shas, _res = await run_chain(
        target, confirmed, model=args.model, context_block=context_block,
        transcript_path=os.path.join(args.results_dir, "chain_transcript.jsonl"))
    print(color(f"  ⛓ composed {len(chains)} chain(s)", "chain"))
    _render(args.results_dir, target.name, rounds, accumulated, triaged, chains, None)
    _final_summary(args.results_dir, triaged, chains)


def cmd_report(args) -> None:
    target_name = _target_from_results(args.results_dir)
    rounds = load_rounds(args.results_dir)
    accumulated = accumulate(rounds)
    verdicts = _load_verdicts(args.results_dir)
    triaged = triage_fn(accumulated, verdicts)
    chains = _load_chains(args.results_dir)
    _render(args.results_dir, target_name, rounds, accumulated, triaged, chains, None)
    print(color(f"  → {os.path.join(args.results_dir, 'REPORT.md')}", "bold"))


# ──────────────────────────────────────────────────────────────────────────────
# render + summary + reload helpers
# ──────────────────────────────────────────────────────────────────────────────

def _render(results_dir, target_name, rounds, accumulated, triaged, chains,
            threat_model, salvo_size=None):
    from .stages.report import write_report
    path = write_report(results_dir, target_name, rounds, accumulated, triaged,
                        chains, threat_model=threat_model, salvo_size=salvo_size)
    return path


def _final_summary(results_dir, triaged, chains):
    confirmed = [t for t in triaged if t.confirmed]
    print(color("\n  ── salvo complete ─────────────────────────────", "cannon"))
    print(f"  unique findings : {len(triaged)}")
    print(f"  confirmed       : {color(str(len(confirmed)), 'bold')}")
    print(f"  attack chains   : {len(chains)}")
    print(f"  report          : {color(os.path.join(results_dir, 'REPORT.md'), 'report')}")
    if confirmed:
        print(color("\n  top confirmed:", "bold"))
        for t in confirmed[:5]:
            f = t.accumulated.representative
            print(f"    • {t.accumulated.max_severity:8} {f.title[:60]}  "
                  f"({f.file}{':' + str(f.line) if f.line else ''})")
    print()


def _target_from_results(results_dir: str) -> str:
    # results/<target>/<ts>/  → <target>
    p = Path(results_dir).resolve()
    return p.parent.name


def _load_verdicts(results_dir: str) -> dict[str, Verdict]:
    p = Path(results_dir, "triage.json")
    if not p.is_file():
        return {}
    out = {}
    for row in json.loads(p.read_text()):
        v = row.get("verdict")
        if v:
            out[row["signature"]] = Verdict.from_dict(v)
    return out


def _load_chains(results_dir: str):
    from .artifacts import Chain
    p = Path(results_dir, "chains.json")
    if not p.is_file():
        return []
    return [Chain.from_dict(c) for c in json.loads(p.read_text())]


# ──────────────────────────────────────────────────────────────────────────────
# argparse
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cannon", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_model(sp):
        sp.add_argument("--model", default=DEFAULT_MODEL, help=f"model (default: {DEFAULT_MODEL})")

    fire = sub.add_parser("fire", help="fire a salvo of permuted scans")
    fire.add_argument("target")
    add_model(fire)
    fire.add_argument("--runs", type=int, default=1, help="repeats per matrix cell")
    fire.add_argument("--concurrency", type=int, default=4, help="max parallel rounds")
    fire.add_argument("--focus", help="explicit focus areas, ';'-separated")
    fire.add_argument("--variants", help="prompt variants, comma-separated")
    fire.add_argument("--models", help="models to permute across, comma-separated")
    fire.add_argument("--threat-model", dest="threat_model", action="store_true",
                      help="run threat-model first; seed focus areas + Mermaid graph")
    fire.add_argument("--recon", action="store_true",
                      help="run recon first to auto-discover focus areas")
    fire.add_argument("--chain", action="store_true",
                      help="compose attack chains from confirmed findings")
    fire.add_argument("--verify-top", dest="verify_top", type=int, default=0,
                      help="only verify the top-N unique findings (0 = all)")
    fire.add_argument("--resume", metavar="RESULTS_DIR",
                      help="resume a partially-fired salvo")
    fire.set_defaults(func=cmd_fire, is_async=True)

    rec = sub.add_parser("recon", help="print a focus-area partition")
    rec.add_argument("target"); add_model(rec)
    rec.set_defaults(func=cmd_recon, is_async=True)

    tm = sub.add_parser("threat-model", help="build THREAT_MODEL.md + Mermaid graph")
    tm.add_argument("target"); add_model(tm)
    tm.set_defaults(func=cmd_threat_model, is_async=True)

    tr = sub.add_parser("triage", help="re-accumulate + verify + report over a results dir")
    tr.add_argument("results_dir"); add_model(tr)
    tr.add_argument("--concurrency", type=int, default=4)
    tr.add_argument("--verify-top", dest="verify_top", type=int, default=0)
    tr.set_defaults(func=cmd_triage, is_async=True)

    ch = sub.add_parser("chain", help="compose attack chains from confirmed findings")
    ch.add_argument("results_dir"); add_model(ch)
    ch.set_defaults(func=cmd_chain, is_async=True)

    rp = sub.add_parser("report", help="re-render REPORT.md from existing artifacts")
    rp.add_argument("results_dir")
    rp.set_defaults(func=cmd_report, is_async=False)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if getattr(args, "is_async", False):
            asyncio.run(args.func(args))
        else:
            args.func(args)
    except KeyboardInterrupt:
        print(color("\n  ⨯ interrupted — partial results checkpointed; "
                    "re-run with --resume <results_dir>", "red"), file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
