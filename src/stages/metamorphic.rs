//! Metamorphic stage: for one finding, an agent identifies the load-bearing
//! control that determines safety, proposes the minimal mutation that would flip
//! it, and judges whether the bug fires as-written (`orig_vulnerable`) and whether
//! the mutation would make it fire (`mutant_vulnerable`). The deterministic
//! `metamorphic::decide` turns those into a verdict.
//!
//! When the agent supplies an executable check and `CANNON_ALLOW_EXEC=1`, cannon
//! materializes the mutant on disk and *runs* original vs. mutant — turning the
//! two booleans into measured facts (`metamorphic::stage_mutation` +
//! `dynamic::reproduce`).

use crate::agent::{parse_xml_tag, run_agent, AgentOpts, AgentResult};
use crate::artifacts::AccumulatedFinding;
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::metamorphic::{decide, stage_mutation, MetamorphicReport};
use crate::prompts::load_prompt;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

fn parse_bool(s: Option<String>) -> bool {
    match s {
        Some(x) => {
            let t = x.trim().to_lowercase();
            t.starts_with('y') || t == "true" || t.starts_with("present") || t.starts_with("vulnerable") || t.starts_with("fires")
        }
        None => false,
    }
}

/// Attempt the execution-grounded differential. Returns Some((orig, mutant)) only
/// when allowed and fully specified; otherwise None (caller falls back to static).
fn try_execute(target: &TargetConfig, text: &str, sig: &str) -> Option<(bool, bool)> {
    if std::env::var("CANNON_ALLOW_EXEC").ok().as_deref() != Some("1") {
        return None;
    }
    let run_command = parse_xml_tag(text, "run_command")?;
    let witness = parse_xml_tag(text, "witness")?;
    let mutation_file = parse_xml_tag(text, "mutation_file")?;
    let find = parse_xml_tag(text, "mutation_find")?;
    let replace = parse_xml_tag(text, "mutation_replace").unwrap_or_default();
    let src = target.source_root.display().to_string();
    let timeout = Duration::from_secs(15);

    // original: expect the witness NOT to fire (the code is, allegedly, safe)
    let orig = crate::dynamic::reproduce(&run_command, "", &src, &target.source_root, &witness, 3, timeout);
    // mutant: remove the load-bearing control, expect the witness to fire
    let tag: String = sig.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let mutant_root = stage_mutation(&target.source_root, &mutation_file, &find, &replace, &tag).ok()?;
    let mutant_src = mutant_root.display().to_string();
    let mutant = crate::dynamic::reproduce(&run_command, "", &mutant_src, &mutant_root, &witness, 3, timeout);
    let _ = std::fs::remove_dir_all(&mutant_root);
    Some((orig.proven(), mutant.proven()))
}

pub async fn run_metamorphic(
    target: &TargetConfig,
    id: &str,
    acc: &AccumulatedFinding,
    model: &str,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<(MetamorphicReport, AgentResult)> {
    let f = &acc.representative;
    let sys = build_system_prompt(target, "default")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("title".into(), f.title.clone());
    vars.insert("severity".into(), f.severity.clone());
    vars.insert("file".into(), f.file.clone());
    vars.insert("line".into(), f.line.map(|l| l.to_string()).unwrap_or_else(|| "unknown".into()));
    vars.insert("cwe".into(), f.cwe.clone().unwrap_or_else(|| "unspecified".into()));
    vars.insert("description".into(), f.description.clone());
    vars.insert("evidence".into(), f.evidence.clone());
    let exec_ok = std::env::var("CANNON_ALLOW_EXEC").ok().as_deref() == Some("1");
    vars.insert(
        "exec_note".into(),
        if exec_ok {
            "Execution is ENABLED (CANNON_ALLOW_EXEC=1). If you can write a self-contained shell check that makes the witness fire only when the bug is live, also emit <run_command>, <witness>, <mutation_file>, <mutation_find>, <mutation_replace> and cannon will run original vs. mutant to MEASURE the two booleans.".into()
        } else {
            "Execution is disabled; reason statically and fill the two booleans from your code reading.".into()
        },
    );

    let prompt = load_prompt("metamorphic", Some(&target.target_dir), "default", &vars)?;
    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix;

    let agent = run_agent(&prompt.text, &opts).await;
    let text = agent.all_text();

    let mutation = parse_xml_tag(&text, "mutation").unwrap_or_default();
    let reasoning = parse_xml_tag(&text, "reasoning").unwrap_or_default();

    // Prefer measured booleans (execution); fall back to the agent's reasoning.
    let (orig_v, mutant_v, executed) = match try_execute(target, &text, &acc.signature) {
        Some((o, m)) => (o, m, true),
        None => (
            parse_bool(parse_xml_tag(&text, "orig_vulnerable")),
            parse_bool(parse_xml_tag(&text, "mutant_vulnerable")),
            false,
        ),
    };

    let verdict = decide(orig_v, mutant_v);
    let report = MetamorphicReport {
        id: id.to_string(),
        signature: acc.signature.clone(),
        verdict: verdict.as_str().to_string(),
        orig_vulnerable: orig_v,
        mutant_vulnerable: mutant_v,
        mutation,
        reasoning,
        executed,
    };
    Ok((report, agent))
}
