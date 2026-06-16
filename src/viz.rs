//! Mermaid emitters for REPORT.md (port of viz.py). The TUI draws its own
//! native graphs (see tui/graph.rs); this is the markdown/HTML surface.

use crate::artifacts::{Chain, Component, DataFlow, TriagedFinding};
use std::collections::BTreeMap;

fn node_id(name: &str, prefix: &str) -> String {
    let mut h = String::new();
    let mut prev = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            h.push(c);
            prev = false;
        } else if !prev {
            h.push('_');
            prev = true;
        }
    }
    let h = h.trim_matches('_');
    let h: String = h.chars().take(32).collect();
    format!("{prefix}_{}", if h.is_empty() { "x".to_string() } else { h })
}

fn esc(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ").trim().to_string()
}

pub fn threat_model_mermaid(components: &[Component], flows: &[DataFlow], boundaries: &[String]) -> String {
    let _ = boundaries;
    if components.is_empty() && flows.is_empty() {
        return String::new();
    }
    let mut lines = vec!["```mermaid".to_string(), "flowchart LR".to_string()];

    let mut by_trust: BTreeMap<String, Vec<&Component>> = BTreeMap::new();
    for c in components {
        let key = if c.trust.is_empty() { "system".to_string() } else { c.trust.clone() };
        by_trust.entry(key).or_default().push(c);
    }

    let mut declared: Vec<String> = Vec::new();
    for (trust, comps) in &by_trust {
        let grouped = trust != "system";
        let indent = if grouped { "    " } else { "  " };
        if grouped {
            lines.push(format!("  subgraph {}[\"{}\"]", node_id(trust, "tb"), esc(trust)));
        }
        for c in comps {
            lines.push(format!("{indent}{}[\"{}\"]", node_id(&c.name, "n"), esc(&c.name)));
            declared.push(c.name.clone());
        }
        if grouped {
            lines.push("  end".to_string());
        }
    }

    for fl in flows {
        let a = node_id(&fl.src, "n");
        let b = node_id(&fl.dst, "n");
        if !declared.contains(&fl.src) {
            lines.push(format!("  {a}[\"{}\"]", esc(&fl.src)));
            declared.push(fl.src.clone());
        }
        if !declared.contains(&fl.dst) {
            lines.push(format!("  {b}[\"{}\"]", esc(&fl.dst)));
            declared.push(fl.dst.clone());
        }
        if fl.label.is_empty() {
            lines.push(format!("  {a} --> {b}"));
        } else {
            lines.push(format!("  {a} -->|\"{}\"| {b}", esc(&fl.label)));
        }
    }
    lines.push("```".to_string());
    lines.join("\n")
}

pub fn chains_mermaid(chains: &[Chain]) -> String {
    if chains.is_empty() {
        return String::new();
    }
    let mut lines = vec!["```mermaid".to_string(), "flowchart LR".to_string()];
    for (ci, c) in chains.iter().enumerate() {
        let sg = node_id(&c.title, &format!("c{ci}"));
        lines.push(format!("  subgraph {sg}[\"{} ({})\"]", esc(&c.title), c.severity));
        let mut prev = format!("{sg}_start");
        let premise: String = esc(if c.premise.is_empty() { "attacker start" } else { &c.premise }).chars().take(60).collect();
        lines.push(format!("    {prev}([\"{premise}\"])"));
        for (si, step) in c.steps.iter().enumerate() {
            let nid = format!("{sg}_s{si}");
            let label_src = if !step.action.is_empty() { &step.action } else { &step.title };
            let label: String = esc(label_src).chars().take(70).collect();
            lines.push(format!("    {nid}[\"{label}\"]"));
            lines.push(format!("    {prev} --> {nid}"));
            prev = nid;
        }
        let end = format!("{sg}_impact");
        let impact: String = esc(if c.impact.is_empty() { "impact" } else { &c.impact }).chars().take(60).collect();
        lines.push(format!("    {end}([\"💥 {impact}\"])"));
        lines.push(format!("    {prev} --> {end}"));
        lines.push("  end".to_string());
    }
    lines.push("```".to_string());
    lines.join("\n")
}

pub fn triage_table(triaged: &[TriagedFinding]) -> String {
    if triaged.is_empty() {
        return "_No findings._".to_string();
    }
    let mut rows = vec![
        "| Rank | Sev | Verdict | Conf | Corrob | Finding | Location |".to_string(),
        "|---:|---|---|---:|---:|---|---|".to_string(),
    ];
    for (i, t) in triaged.iter().enumerate() {
        let f = &t.accumulated.representative;
        let mark = if t.confirmed() {
            "✅"
        } else if t.verdict.verdict == "FALSE_POSITIVE" {
            "❌"
        } else {
            "❔"
        };
        rows.push(format!(
            "| {} | {} | {} {} | {:.2} | {} | {} | `{}` |",
            i + 1,
            t.accumulated.max_severity,
            mark,
            t.verdict.verdict,
            t.verdict.confidence,
            t.accumulated.corroboration,
            esc(&f.title),
            esc(&f.loc())
        ));
    }
    rows.join("\n")
}
