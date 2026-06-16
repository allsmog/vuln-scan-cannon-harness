//! Semantic dedup: a judge agent collapses findings that the signature-based
//! pass missed (same root cause at different lines/files). Opt-in via --dedup.

use crate::agent::{parse_all_tags, run_agent, AgentOpts};
use crate::artifacts::{sev_rank, AccumulatedFinding};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn catalog(accs: &[AccumulatedFinding]) -> String {
    accs.iter()
        .map(|a| format!("[{}] {} {} @ {}", a.signature, a.max_severity, a.representative.title, a.representative.loc()))
        .collect::<Vec<_>>()
        .join("\n")
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
    let mut vars = BTreeMap::new();
    vars.insert("findings_catalog".to_string(), catalog(&accumulated));
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
