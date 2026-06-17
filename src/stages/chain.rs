//! Attack-chain stage: take CONFIRMED/triaged findings and compose multi-step
//! attack chains. Emits structured <chain> blocks → Chain objects.

use crate::agent::{parse_all_tags, parse_xml_tag, run_agent, AgentOpts, AgentResult};
use crate::artifacts::{norm_severity, Chain, ChainStep};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A finding offered to the chain composer (built by the caller from the ledger
/// or from a run's triaged set).
pub struct ChainCandidate {
    pub signature: String,
    pub title: String,
    pub loc: String,
    pub severity: String,
    pub premise: String,
    pub description: String,
}

fn catalog(candidates: &[ChainCandidate]) -> String {
    candidates
        .iter()
        .map(|c| {
            let desc: String = c.description.chars().take(240).collect();
            let premise = if c.premise.is_empty() { "(none stated)" } else { &c.premise };
            format!(
                "- [{}] {} {} @ {}\n    premise: {}\n    what it gives the attacker: {}",
                c.signature, c.severity, c.title, c.loc, premise, desc
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_chain_block(block: &str, sig_titles: &BTreeMap<String, String>) -> Option<Chain> {
    let title = parse_xml_tag(block, "title")?;
    if title.is_empty() {
        return None;
    }
    let mut steps = Vec::new();
    for raw in parse_all_tags(block, "step") {
        let (sig, action) = match raw.split_once('|') {
            Some((s, a)) => (s.trim().trim_matches(['[', ']']).to_string(), a.trim().to_string()),
            None => (String::new(), raw.trim().to_string()),
        };
        let sig = if sig == "-" { String::new() } else { sig };
        let title = sig_titles.get(&sig).cloned().unwrap_or_default();
        steps.push(ChainStep { signature: sig, title, action });
    }
    Some(Chain {
        title,
        premise: parse_xml_tag(block, "premise").unwrap_or_default(),
        steps,
        impact: parse_xml_tag(block, "impact").unwrap_or_default(),
        severity: norm_severity(&parse_xml_tag(block, "severity").unwrap_or_default()),
    })
}

pub async fn run_chain(
    target: &TargetConfig,
    candidates: &[ChainCandidate],
    model: &str,
    context_block: &str,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<(Vec<Chain>, BTreeMap<String, String>, AgentResult)> {
    if candidates.is_empty() {
        return Ok((Vec::new(), BTreeMap::new(), AgentResult::default()));
    }
    let sys = build_system_prompt(target, "default")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("findings_catalog".into(), catalog(candidates));
    vars.insert(
        "context".into(),
        if context_block.is_empty() { "(no project context documents were provided)".into() } else { context_block.to_string() },
    );
    let chain = load_prompt("chain", Some(&target.target_dir), "default", &vars)?;

    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix;

    let agent = run_agent(&chain.text, &opts).await;

    let sig_titles: BTreeMap<String, String> =
        candidates.iter().map(|c| (c.signature.clone(), c.title.clone())).collect();
    let mut chains = Vec::new();
    for block in parse_all_tags(&agent.all_text(), "chain") {
        if let Some(c) = parse_chain_block(&block, &sig_titles) {
            chains.push(c);
        }
    }

    let mut shas = BTreeMap::new();
    shas.insert("system".into(), sys.sha256.clone());
    shas.insert("chain".into(), chain.sha256.clone());
    Ok((chains, shas, agent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chain_block_with_steps_and_titles() {
        let mut titles = BTreeMap::new();
        titles.insert("app.py:10:1".to_string(), "SQLi".to_string());
        let block = "<title>SQLi to RCE</title>\
            <premise>unauthenticated remote attacker</premise>\
            <severity>critical</severity>\
            <impact>full host takeover</impact>\
            <step>[app.py:10:1] | exploit the SQLi to write a webshell</step>\
            <step>- | pivot from the webshell to a root shell</step>";
        let c = parse_chain_block(block, &titles).unwrap();
        assert_eq!(c.title, "SQLi to RCE");
        assert_eq!(c.severity, "CRITICAL");
        assert_eq!(c.premise, "unauthenticated remote attacker");
        assert_eq!(c.steps.len(), 2);
        assert_eq!(c.steps[0].signature, "app.py:10:1");
        assert_eq!(c.steps[0].title, "SQLi", "known signatures resolve to their finding title");
        assert_eq!(c.steps[1].signature, "", "'-' is normalized to an empty signature");
    }

    #[test]
    fn chain_block_without_title_is_dropped() {
        assert!(parse_chain_block("<premise>x</premise><step>a</step>", &BTreeMap::new()).is_none());
        assert!(parse_chain_block("<title></title>", &BTreeMap::new()).is_none());
    }
}
