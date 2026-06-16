//! Detector registry / dispatch. A detector turns one Spec into one RoundResult.
//!
//!   static_review — LLM agent reads source, emits findings (default)
//!   secrets       — deterministic, LLM-free secret/entropy scan
//!   dynamic       — builds + runs the target, proves findings with a witness
//!
//! Adding a detector = a new arm here + a module; the runner/triage/ledger above
//! it are unchanged.

use crate::artifacts::RoundResult;
use crate::config::TargetConfig;
use crate::permute::Spec;
use crate::stages::find::run_find;
use std::collections::BTreeMap;
use std::path::Path;

pub async fn run_round(
    target: &TargetConfig,
    spec: &Spec,
    context_block: &str,
    out_dir: &Path,
    progress_prefix: Option<String>,
) -> RoundResult {
    match target.detector.as_str() {
        "secrets" => secrets_round(target, spec),
        "dynamic" => crate::dynamic::run_round(target, spec, out_dir, progress_prefix).await,
        _ => static_review_round(target, spec, context_block, out_dir, progress_prefix).await,
    }
}

fn round_result(target: &TargetConfig, spec: &Spec, status: &str, findings: Vec<crate::artifacts::Finding>) -> RoundResult {
    RoundResult {
        target: target.name.clone(),
        label: spec.label.clone(),
        status: status.to_string(),
        focus_area: spec.focus_area.clone(),
        variant: spec.variant.clone(),
        model: spec.model.clone(),
        findings,
        prompt_shas: BTreeMap::new(),
        prompt_sources: BTreeMap::new(),
        timings: BTreeMap::new(),
        session_id: None,
        error: None,
    }
}

/// Deterministic secrets detector — no agent.
fn secrets_round(target: &TargetConfig, spec: &Spec) -> RoundResult {
    let mut findings = crate::secrets::scan_dir(&target.source_root);
    for f in &mut findings {
        f.round_label = Some(spec.label.clone());
        f.focus_area = spec.focus_area.clone();
    }
    let status = if findings.is_empty() { "no_findings" } else { "completed" };
    round_result(target, spec, status, findings)
}

async fn static_review_round(
    target: &TargetConfig,
    spec: &Spec,
    context_block: &str,
    out_dir: &Path,
    progress_prefix: Option<String>,
) -> RoundResult {
    let _ = std::fs::create_dir_all(out_dir);
    let transcript = out_dir.join("find_transcript.jsonl");

    match run_find(target, spec, context_block, Some(transcript), progress_prefix).await {
        Ok(o) => {
            let status = if o.agent.error.is_some() {
                "agent_failed"
            } else if !o.findings.is_empty() {
                "completed"
            } else {
                "no_findings"
            };
            let mut timings = BTreeMap::new();
            timings.insert("find".to_string(), (o.elapsed * 10.0).round() / 10.0);
            if o.self_refuted > 0 {
                // findings the finder's own taint trace disproved and dropped
                timings.insert("self_refuted".to_string(), o.self_refuted as f64);
            }
            RoundResult {
                target: target.name.clone(),
                label: spec.label.clone(),
                status: status.to_string(),
                focus_area: spec.focus_area.clone(),
                variant: spec.variant.clone(),
                model: spec.model.clone(),
                findings: o.findings,
                prompt_shas: o.prompt_shas,
                prompt_sources: o.prompt_sources,
                timings,
                session_id: o.agent.session_id,
                error: o.agent.error,
            }
        }
        Err(e) => {
            let mut r = round_result(target, spec, "error", Vec::new());
            r.error = Some(format!("{e}"));
            r
        }
    }
}
