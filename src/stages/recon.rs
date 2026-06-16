//! Recon stage: partition the attack surface into focus areas. Emits <focus_areas>.

use crate::agent::{parse_xml_tag, run_agent, AgentOpts, AgentResult};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub async fn run_recon(
    target: &TargetConfig,
    model: &str,
    context_block: &str,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<(Vec<String>, AgentResult)> {
    let sys = build_system_prompt(target, "default")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("language".into(), target.language.clone().unwrap_or_else(|| "unspecified".into()));
    vars.insert(
        "context".into(),
        if context_block.is_empty() { "(no project context documents were provided)".into() } else { context_block.to_string() },
    );
    let recon = load_prompt("recon", Some(&target.target_dir), "default", &vars)?;

    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix;

    let agent = run_agent(&recon.text, &opts).await;
    let raw = parse_xml_tag(&agent.find_tagged_message("focus_areas"), "focus_areas");
    let areas = raw
        .map(|r| {
            r.lines()
                .map(|l| l.trim_matches([' ', '-', '\t']).to_string())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok((areas, agent))
}
