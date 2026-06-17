//! Patch stage: for a confirmed finding, a patch agent proposes a minimal
//! unified diff, then an INDEPENDENT reviewer (who sees only the diff + the
//! location, not the author's rationale) judges it. Read-only: the diff is a
//! draft for the human, never applied.

use crate::agent::{parse_xml_tag, run_agent, AgentOpts};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub struct PatchCandidate {
    pub id: String,
    pub title: String,
    pub file: String,
    pub line: Option<u32>,
    pub severity: String,
    pub cwe: Option<String>,
    pub description: String,
}

#[derive(Serialize)]
pub struct PatchResult {
    pub id: String,
    pub file: String,
    pub diff: String,
    pub rationale: String,
    pub review: String, // APPROVED | CONCERNS | none
    pub review_notes: String,
}

fn strip_fence(s: &str) -> String {
    let t = s.trim();
    if t.starts_with("```") {
        let mut lines: Vec<&str> = t.lines().collect();
        if !lines.is_empty() {
            lines.remove(0);
        }
        if lines.last().map(|l| l.trim_start().starts_with("```")).unwrap_or(false) {
            lines.pop();
        }
        return lines.join("\n");
    }
    t.to_string()
}

/// A non-fatal patch failure (e.g. a missing prompt template): surfaced in the
/// output rather than panicking the whole `cannon patch` run.
fn patch_err(cand: &PatchCandidate, diff: String, msg: String) -> PatchResult {
    PatchResult {
        id: cand.id.clone(),
        file: cand.file.clone(),
        diff,
        rationale: String::new(),
        review: "error".into(),
        review_notes: msg,
    }
}

pub async fn run_patch_one(
    target: &TargetConfig,
    cand: &PatchCandidate,
    model: &str,
    out_dir: &Path,
    progress_prefix: Option<String>,
) -> PatchResult {
    let sys = match build_system_prompt(target, "default") {
        Ok(s) => s,
        Err(e) => return patch_err(cand, String::new(), format!("system prompt: {e}")),
    };
    let line_s = cand.line.map(|l| l.to_string()).unwrap_or_else(|| "unknown".into());
    let cwe_s = cand.cwe.clone().unwrap_or_else(|| "unspecified".into());

    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("title".into(), cand.title.clone());
    vars.insert("severity".into(), cand.severity.clone());
    vars.insert("file".into(), cand.file.clone());
    vars.insert("line".into(), line_s.clone());
    vars.insert("cwe".into(), cwe_s.clone());
    vars.insert("description".into(), cand.description.clone());
    let patch_prompt = match load_prompt("patch", Some(&target.target_dir), "default", &vars) {
        Ok(p) => p,
        Err(e) => return patch_err(cand, String::new(), format!("patch prompt: {e}")),
    };

    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = Some(out_dir.join(format!("{}.patch.jsonl", cand.id)));
    opts.progress_prefix = progress_prefix.clone();
    let agent = run_agent(&patch_prompt.text, &opts).await;
    let text = agent.find_tagged_message("patch");
    let diff = strip_fence(&parse_xml_tag(&text, "patch").unwrap_or_default());
    let rationale = parse_xml_tag(&text, "rationale").unwrap_or_default();

    if diff.trim().is_empty() {
        return PatchResult {
            id: cand.id.clone(),
            file: cand.file.clone(),
            diff: String::new(),
            rationale,
            review: "none".into(),
            review_notes: "no patch produced".into(),
        };
    }

    // Independent review — sees only the diff + location, not the rationale.
    let mut rvars: BTreeMap<String, String> = BTreeMap::new();
    rvars.insert("source_root".into(), target.source_root.display().to_string());
    rvars.insert("file".into(), cand.file.clone());
    rvars.insert("line".into(), line_s);
    rvars.insert("cwe".into(), cwe_s);
    rvars.insert("diff".into(), diff.clone());
    let review_prompt = match load_prompt("patch_review", Some(&target.target_dir), "default", &rvars) {
        Ok(p) => p,
        // Keep the generated diff; just flag that review couldn't run.
        Err(e) => return patch_err(cand, diff, format!("patch_review prompt: {e}")),
    };
    let mut ropts = AgentOpts::new(model);
    ropts.cwd = Some(target.source_root.clone());
    ropts.system_prompt = Some(sys.text.clone());
    ropts.transcript_path = Some(out_dir.join(format!("{}.review.jsonl", cand.id)));
    ropts.progress_prefix = progress_prefix;
    let ragent = run_agent(&review_prompt.text, &ropts).await;
    let rtext = ragent.find_tagged_message("review");
    let review = parse_xml_tag(&rtext, "review")
        .map(|s| if s.to_uppercase().contains("APPROV") { "APPROVED".to_string() } else { "CONCERNS".to_string() })
        .unwrap_or_else(|| "CONCERNS".to_string());
    let review_notes = parse_xml_tag(&rtext, "notes").unwrap_or_default();

    let _ = crate::lock::write_atomic(&out_dir.join(format!("{}.diff", cand.id)), diff.as_bytes());

    PatchResult { id: cand.id.clone(), file: cand.file.clone(), diff, rationale, review, review_notes }
}
