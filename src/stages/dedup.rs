//! Semantic dedup: a judge agent collapses findings that the signature-based
//! pass missed (same root cause at different lines/files). Opt-in via --dedup.

use crate::agent::{parse_all_tags, run_agent, AgentOpts};
use crate::artifacts::{sev_rank, AccumulatedFinding};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Cap on how many findings are listed in the dedup prompt. Past this, the
/// catalog (and thus context/cost) would grow unbounded on a huge findings set;
/// the dedup pass is best-effort, so the tail simply passes through un-deduped.
const MAX_DEDUP_CATALOG: usize = 300;

/// Render the catalog, most-severe first so a cap keeps the important findings.
/// Returns the text and how many findings were omitted by the cap.
fn catalog(accs: &[AccumulatedFinding]) -> (String, usize) {
    let mut ordered: Vec<&AccumulatedFinding> = accs.iter().collect();
    ordered.sort_by_key(|a| std::cmp::Reverse(sev_rank(&a.max_severity)));
    let omitted = ordered.len().saturating_sub(MAX_DEDUP_CATALOG);
    let text = ordered
        .iter()
        .take(MAX_DEDUP_CATALOG)
        .map(|a| format!("[{}] {} {} @ {}", a.signature, a.max_severity, a.representative.title, a.representative.loc()))
        .collect::<Vec<_>>()
        .join("\n");
    (text, omitted)
}

pub async fn run_dedup(
    target: &TargetConfig,
    accumulated: Vec<AccumulatedFinding>,
    model: &str,
    transcript: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> Vec<AccumulatedFinding> {
    if accumulated.len() < 2 {
        return accumulated;
    }
    let sys = match build_system_prompt(target, "default") {
        Ok(s) => s,
        Err(_) => return accumulated,
    };
    let (catalog_text, omitted) = catalog(&accumulated);
    if omitted > 0 {
        eprintln!(
            "{}",
            crate::ui::ecolor(&format!("  ⚠ dedup: catalog capped at {MAX_DEDUP_CATALOG}; {omitted} lower-severity finding(s) skipped (they pass through un-deduped)"), "dim")
        );
    }
    let mut vars = BTreeMap::new();
    vars.insert("findings_catalog".to_string(), catalog_text);
    let p = match load_prompt("dedup", Some(&target.target_dir), "default", &vars) {
        Ok(p) => p,
        Err(_) => return accumulated,
    };
    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    opts.system_prompt = Some(sys.text);
    opts.transcript_path = transcript;
    opts.progress_prefix = progress_prefix;
    let agent = run_agent(&p.text, &opts).await;

    let mut groups: Vec<Vec<String>> = Vec::new();
    for block in parse_all_tags(&agent.all_text(), "duplicate") {
        let sigs: Vec<String> = block
            .split(',')
            .map(|s| s.trim().trim_matches(['[', ']']).to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if sigs.len() >= 2 {
            groups.push(sigs);
        }
    }
    if groups.is_empty() {
        return accumulated;
    }

    let mut by_sig: BTreeMap<String, AccumulatedFinding> =
        accumulated.into_iter().map(|a| (a.signature.clone(), a)).collect();
    let mut dropped: BTreeSet<String> = BTreeSet::new();

    for group in groups {
        let present: Vec<String> = group
            .iter()
            .filter(|s| by_sig.contains_key(*s) && !dropped.contains(*s))
            .cloned()
            .collect();
        if present.len() < 2 {
            continue;
        }
        let keep = present.iter().max_by_key(|s| sev_rank(&by_sig[*s].max_severity)).unwrap().clone();
        let mut rounds = by_sig[&keep].rounds.clone();
        for s in &present {
            if s == &keep {
                continue;
            }
            if let Some(other) = by_sig.get(s) {
                for r in &other.rounds {
                    if !rounds.contains(r) {
                        rounds.push(r.clone());
                    }
                }
            }
            dropped.insert(s.clone());
        }
        if let Some(k) = by_sig.get_mut(&keep) {
            k.corroboration = rounds.len().max(k.corroboration);
            k.rounds = rounds;
        }
    }

    let mut out: Vec<AccumulatedFinding> =
        by_sig.into_iter().filter(|(s, _)| !dropped.contains(s)).map(|(_, a)| a).collect();
    out.sort_by(|a, b| {
        (sev_rank(&b.max_severity), b.corroboration).cmp(&(sev_rank(&a.max_severity), a.corroboration))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::Finding;

    fn acc(sig: &str, sev: &str) -> AccumulatedFinding {
        AccumulatedFinding {
            signature: sig.to_string(),
            representative: Finding { title: format!("t-{sig}"), file: "app.py".into(), ..Default::default() },
            corroboration: 1,
            rounds: vec!["r0".into()],
            max_severity: sev.to_string(),
        }
    }

    #[test]
    fn catalog_caps_and_reports_omitted() {
        let n = MAX_DEDUP_CATALOG + 25;
        let accs: Vec<AccumulatedFinding> = (0..n).map(|i| acc(&format!("sig{i}"), "LOW")).collect();
        let (text, omitted) = catalog(&accs);
        assert_eq!(omitted, 25, "should report the count beyond the cap");
        assert_eq!(text.lines().count(), MAX_DEDUP_CATALOG, "catalog must be capped");
    }

    #[test]
    fn catalog_keeps_most_severe_when_capped() {
        // One CRITICAL among many LOWs past the cap — it must survive the cap.
        let mut accs: Vec<AccumulatedFinding> = (0..MAX_DEDUP_CATALOG + 50).map(|i| acc(&format!("low{i}"), "LOW")).collect();
        accs.push(acc("crit-1", "CRITICAL"));
        let (text, _) = catalog(&accs);
        assert!(text.contains("crit-1"), "the CRITICAL finding must be kept under the cap");
    }

    #[test]
    fn catalog_small_set_unchanged() {
        let accs = vec![acc("a", "HIGH"), acc("b", "LOW")];
        let (text, omitted) = catalog(&accs);
        assert_eq!(omitted, 0);
        assert_eq!(text.lines().count(), 2);
    }
}
