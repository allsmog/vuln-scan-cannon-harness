//! Threat-model stage: read code + context, emit a narrative threat model, a
//! component/data-flow graph (for the TUI canvas + Mermaid), and seed focus areas.

use crate::agent::{parse_all_tags, parse_xml_tag, run_agent, AgentOpts, AgentResult};
use crate::artifacts::{Component, DataFlow, ThreatModel};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn parse_components(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for block in parse_all_tags(text, "component") {
        let parts: Vec<String> = block.split('|').map(|p| p.trim().to_string()).collect();
        if parts.is_empty() || parts[0].is_empty() {
            continue;
        }
        out.push(Component {
            name: parts[0].clone(),
            trust: parts.get(1).cloned().unwrap_or_default(),
            description: parts.get(2).cloned().unwrap_or_default(),
        });
    }
    out
}

fn parse_flows(text: &str) -> Vec<DataFlow> {
    let mut out = Vec::new();
    for block in parse_all_tags(text, "data_flow") {
        let (body, label) = match block.split_once(':') {
            Some((b, l)) => (b.to_string(), l.trim().to_string()),
            None => (block.clone(), String::new()),
        };
        if let Some((src, dst)) = body.split_once("->") {
            out.push(DataFlow {
                src: src.trim().to_string(),
                dst: dst.trim().to_string(),
                label,
            });
        }
    }
    out
}

pub async fn run_threat_model(
    target: &TargetConfig,
    model: &str,
    context_block: &str,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<(ThreatModel, BTreeMap<String, String>, AgentResult)> {
    let sys = build_system_prompt(target, "default")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("language".into(), target.language.clone().unwrap_or_else(|| "unspecified".into()));
    vars.insert("description".into(), target.description.clone().unwrap_or_else(|| "(no description provided)".into()));
    vars.insert(
        "context".into(),
        if context_block.is_empty() { "(no project context documents were provided)".into() } else { context_block.to_string() },
    );
    let tm = load_prompt("threat_model", Some(&target.target_dir), "default", &vars)?;

    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix;

    let agent = run_agent(&tm.text, &opts).await;
    let text = agent.all_text();

    let narrative = parse_xml_tag(&text, "threat_model").unwrap_or_default();
    let focus_areas = parse_xml_tag(&text, "focus_areas")
        .map(|r| {
            r.lines()
                .map(|l| l.trim_matches([' ', '-', '\t']).to_string())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let boundaries = parse_xml_tag(&text, "trust_boundary")
        .map(|r| r.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect::<Vec<_>>())
        .unwrap_or_default();

    let model_out = ThreatModel {
        narrative,
        components: parse_components(&text),
        flows: parse_flows(&text),
        boundaries,
        focus_areas,
    };

    let mut shas = BTreeMap::new();
    shas.insert("system".into(), sys.sha256.clone());
    shas.insert("threat_model".into(), tm.sha256.clone());
    Ok((model_out, shas, agent))
}
