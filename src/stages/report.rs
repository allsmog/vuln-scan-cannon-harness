//! Report stage: assemble human + machine artifacts. Deterministic (no agent).

use crate::artifacts::{AccumulatedFinding, Chain, RoundResult, ThreatModel, TriagedFinding};
use crate::viz::{chains_mermaid, threat_model_mermaid, triage_table};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

fn strip_fences(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("```") {
        let mut lines: Vec<&str> = s.lines().collect();
        if lines.len() >= 2 {
            lines.remove(0);
            if lines.last().map(|l| l.trim_start().starts_with("```")).unwrap_or(false) {
                lines.pop();
            }
            return lines.join("\n").trim().to_string();
        }
    }
    s.to_string()
}

pub fn write_threat_model(dir: &Path, tm: &ThreatModel) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let graph = threat_model_mermaid(&tm.components, &tm.flows, &tm.boundaries);
    let mut parts = vec!["# Threat model\n".to_string()];
    parts.push(if tm.narrative.is_empty() { "_(no narrative emitted)_".into() } else { tm.narrative.clone() });
    if !graph.is_empty() {
        parts.push(format!("\n## System / data-flow graph\n\n{graph}"));
    }
    if !tm.boundaries.is_empty() {
        parts.push(format!("\n## Trust boundaries\n\n{}", tm.boundaries.iter().map(|b| format!("- {b}")).collect::<Vec<_>>().join("\n")));
    }
    if !tm.focus_areas.is_empty() {
        parts.push(format!("\n## Seeded focus areas\n\n{}", tm.focus_areas.iter().map(|a| format!("- {a}")).collect::<Vec<_>>().join("\n")));
    }
    std::fs::write(dir.join("THREAT_MODEL.md"), format!("{}\n", parts.join("\n")))?;
    std::fs::write(dir.join("threat_model.json"), serde_json::to_string_pretty(tm)?)?;
    Ok(())
}

fn confirmed_detail(t: &TriagedFinding) -> String {
    let f = &t.accumulated.representative;
    let mut out = vec![
        format!("### {} — {}", f.severity, f.title),
        format!("- **Location:** `{}`", f.loc()),
        format!("- **CWE:** {}", f.cwe.clone().unwrap_or_else(|| "unspecified".into())),
        format!("- **Signature:** `{}`", t.accumulated.signature),
        format!("- **Corroboration:** {} round(s) — {}", t.accumulated.corroboration, t.accumulated.rounds.join(", ")),
        format!("- **Verifier confidence:** {:.2}", t.verdict.confidence),
        String::new(),
        f.description.clone(),
    ];
    if !f.exploit_premise.is_empty() {
        out.push(String::new());
        out.push(format!("**Exploit premise:** {}", f.exploit_premise));
    }
    if !f.taint_path.is_empty() || f.taint_status.is_some() {
        out.push(String::new());
        let grounded = if f.taint_grounded() { " _(grounded)_" } else { "" };
        out.push(format!("**Resolved taint path{grounded}:** {}", f.taint_summary()));
    }
    if !f.evidence.is_empty() {
        let ev: String = strip_fences(&f.evidence).chars().take(1500).collect();
        out.push(String::new());
        out.push("**Evidence:**".into());
        out.push(String::new());
        out.push("```".into());
        out.push(ev);
        out.push("```".into());
    }
    if !t.verdict.reasoning.is_empty() {
        out.push(String::new());
        out.push(format!("**Verifier reasoning:** {}", t.verdict.reasoning));
    }
    out.join("\n")
}

/// Persist chains as machine JSON + human CHAINS.md into `dir`.
pub fn write_chains(dir: &Path, chains: &[Chain]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("chains.json"), serde_json::to_string_pretty(chains)?)?;
    std::fs::write(dir.join("CHAINS.md"), format!("# Attack chains\n\n{}\n", chains_section(chains)))?;
    Ok(())
}

fn chains_section(chains: &[Chain]) -> String {
    if chains.is_empty() {
        return "_No multi-step chains composed._".into();
    }
    let mut parts = vec![chains_mermaid(chains), String::new()];
    for c in chains {
        parts.push(format!("### {} — {}", c.severity, c.title));
        parts.push(format!("- **Premise:** {}", c.premise));
        parts.push(format!("- **Impact:** {}", c.impact));
        parts.push("- **Steps:**".into());
        for (i, s) in c.steps.iter().enumerate() {
            let r = if s.signature.is_empty() { String::new() } else { format!(" `[{}]`", s.signature) };
            parts.push(format!("  {}. {}{}", i + 1, s.action, r));
        }
        parts.push(String::new());
    }
    parts.join("\n")
}

#[allow(clippy::too_many_arguments)]
pub fn write_report(
    results_dir: &Path,
    target_name: &str,
    rounds: &[RoundResult],
    accumulated: &[AccumulatedFinding],
    triaged: &[TriagedFinding],
    chains: &[Chain],
    threat_model: Option<&ThreatModel>,
    salvo_size: usize,
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(results_dir)?;
    std::fs::write(results_dir.join("findings_accumulated.json"), serde_json::to_string_pretty(accumulated)?)?;
    std::fs::write(results_dir.join("triage.json"), serde_json::to_string_pretty(triaged)?)?;
    std::fs::write(results_dir.join("chains.json"), serde_json::to_string_pretty(chains)?)?;

    // SARIF of confirmed findings — for GitHub code scanning / CI upload.
    let sarif_rows: Vec<crate::sarif::SarifRow> = triaged
        .iter()
        .filter(|t| t.confirmed())
        .map(|t| {
            let f = &t.accumulated.representative;
            crate::sarif::SarifRow {
                rule_id: crate::sarif::rule_id(f.cwe.as_deref(), &f.title),
                severity: t.verdict.derived_severity.clone().unwrap_or_else(|| t.accumulated.max_severity.clone()),
                file: f.file.clone(),
                line: f.line,
                message: f.title.clone(),
            }
        })
        .collect();
    std::fs::write(
        results_dir.join("report.sarif"),
        serde_json::to_string_pretty(&crate::sarif::build_sarif("cannon", &sarif_rows))?,
    )?;

    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in rounds {
        *status_counts.entry(r.status.clone()).or_insert(0) += 1;
    }
    let raw: usize = rounds.iter().map(|r| r.findings.len()).sum();
    let confirmed: Vec<&TriagedFinding> = triaged.iter().filter(|t| t.confirmed()).collect();

    let mut md = vec![
        format!("# Cannon report — {target_name}"),
        format!("_Generated {}_", chrono::Local::now().format("%Y-%m-%d %H:%M")),
        String::new(),
        "## Salvo".into(),
        format!("- **Rounds fired:** {salvo_size}"),
        format!("- **Round outcomes:** {}", status_counts.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")),
        format!("- **Raw findings:** {raw}  →  **unique:** {}  →  **confirmed:** {}", accumulated.len(), confirmed.len()),
        String::new(),
    ];

    if let Some(tm) = threat_model {
        let graph = threat_model_mermaid(&tm.components, &tm.flows, &tm.boundaries);
        md.push("## Threat model".into());
        md.push(String::new());
        md.push("See [THREAT_MODEL.md](THREAT_MODEL.md).".into());
        md.push(String::new());
        if !graph.is_empty() {
            md.push(graph);
            md.push(String::new());
        }
    }

    md.push("## Triage (ranked)".into());
    md.push(String::new());
    md.push(triage_table(triaged));
    md.push(String::new());

    if !confirmed.is_empty() {
        md.push("## Confirmed findings".into());
        md.push(String::new());
        for t in &confirmed {
            md.push(format!("{}\n", confirmed_detail(t)));
        }
    }

    md.push("## Attack chains".into());
    md.push(String::new());
    md.push(chains_section(chains));
    md.push(String::new());

    md.push("## Appendix — salvo provenance".into());
    md.push(String::new());
    md.push("| Round | Status | Focus | Model | find prompt | system prompt |".into());
    md.push("|---|---|---|---|---|---|".into());
    for r in rounds {
        md.push(format!(
            "| {} | {} | {} | {} | `{}` | `{}` |",
            r.label,
            r.status,
            r.focus_area.clone().unwrap_or_else(|| "—".into()),
            r.model,
            r.prompt_shas.get("find").cloned().unwrap_or_else(|| "—".into()),
            r.prompt_shas.get("system").cloned().unwrap_or_else(|| "—".into()),
        ));
    }
    md.push(String::new());

    let out = results_dir.join("REPORT.md");
    std::fs::write(&out, md.join("\n"))?;
    if !chains.is_empty() {
        std::fs::write(results_dir.join("CHAINS.md"), format!("# Attack chains\n\n{}\n", chains_section(chains)))?;
    }
    Ok(out)
}
