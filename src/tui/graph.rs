//! Native in-terminal graph layout for the Ratatui canvas.
//!
//! The threat model is laid out as COLUMNS BY TRUST TIER (untrusted-input →
//! trusted-core → datastore → external), so the trust boundaries are the
//! columns. Attack chains are laid out as left-to-right lanes.

use crate::artifacts::{Chain, ThreatModel};
use ratatui::style::Color;

pub const W: f64 = 100.0;
pub const H: f64 = 100.0;

pub struct GNode {
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub color: Color,
    pub highlight: bool,
}

pub struct GEdge {
    pub x1: f64,
    pub y1: f64,
    pub x2: f64,
    pub y2: f64,
    pub color: Color,
}

#[derive(Default)]
pub struct GraphLayout {
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
    pub empty_msg: Option<String>,
}

const TIERS: [&str; 5] = ["untrusted-input", "trusted-core", "datastore", "external", "other"];

fn tier_index(trust: &str) -> usize {
    let t = trust.to_lowercase();
    for (i, name) in TIERS.iter().enumerate() {
        if t.contains(name) {
            return i;
        }
    }
    // common synonyms
    if t.contains("untrust") || t.contains("input") || t.contains("external-input") {
        0
    } else if t.contains("db") || t.contains("data") || t.contains("store") {
        2
    } else if t.contains("ext") {
        3
    } else {
        4
    }
}

fn trunc(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

pub fn threat_layout(tm: &ThreatModel, selected_file: Option<&str>) -> GraphLayout {
    if tm.components.is_empty() && tm.flows.is_empty() {
        return GraphLayout { empty_msg: Some("no threat model — run `cannon threat-model`".into()), ..Default::default() };
    }

    // Bucket components by tier, preserving order.
    let mut buckets: Vec<Vec<&crate::artifacts::Component>> = vec![Vec::new(); TIERS.len()];
    for c in &tm.components {
        buckets[tier_index(&c.trust)].push(c);
    }
    // Non-empty tiers become columns.
    let cols: Vec<usize> = (0..TIERS.len()).filter(|i| !buckets[*i].is_empty()).collect();
    let ncols = cols.len().max(1);

    let mut nodes: Vec<GNode> = Vec::new();
    let mut pos: std::collections::HashMap<String, (f64, f64)> = std::collections::HashMap::new();
    let sel_base = selected_file.map(|f| f.rsplit('/').next().unwrap_or(f).to_lowercase());

    for (ci, &tier) in cols.iter().enumerate() {
        let comps = &buckets[tier];
        let m = comps.len().max(1);
        let x = (ci as f64 + 0.5) / ncols as f64 * W;
        for (ri, c) in comps.iter().enumerate() {
            let y = H - (ri as f64 + 0.5) / m as f64 * H;
            pos.insert(c.name.clone(), (x, y));
            let hl = match &sel_base {
                Some(sf) => sf.contains(&c.name.to_lowercase()) || c.name.to_lowercase().contains(sf.trim_end_matches(".py").trim_end_matches(".rs")),
                None => false,
            };
            let color = match tier {
                0 => Color::LightRed,
                1 => Color::Cyan,
                2 => Color::Yellow,
                3 => Color::Magenta,
                _ => Color::Gray,
            };
            nodes.push(GNode { label: trunc(&c.name, 16), x, y, color, highlight: hl });
        }
    }

    let mut edges = Vec::new();
    for fl in &tm.flows {
        if let (Some(&(x1, y1)), Some(&(x2, y2))) = (pos.get(&fl.src), pos.get(&fl.dst)) {
            edges.push(GEdge { x1, y1, x2, y2, color: Color::DarkGray });
        }
    }

    GraphLayout { nodes, edges, empty_msg: None }
}

fn sev_color(sev: &str) -> Color {
    match crate::artifacts::norm_severity(sev).as_str() {
        "CRITICAL" => Color::LightRed,
        "HIGH" => Color::Red,
        "MEDIUM" => Color::Yellow,
        "LOW" => Color::Blue,
        _ => Color::Gray,
    }
}

pub fn chains_layout(chains: &[Chain]) -> GraphLayout {
    if chains.is_empty() {
        return GraphLayout { empty_msg: Some("no chains — press [r] to compose over confirmed findings".into()), ..Default::default() };
    }
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let m = chains.len().max(1);
    for (ci, c) in chains.iter().enumerate() {
        let y = H - (ci as f64 + 0.5) / m as f64 * H;
        let color = sev_color(&c.severity);
        // premise + steps + impact
        let mut labels: Vec<String> = vec![trunc(if c.premise.is_empty() { "start" } else { &c.premise }, 12)];
        for s in &c.steps {
            labels.push(trunc(if s.action.is_empty() { &s.title } else { &s.action }, 12));
        }
        labels.push(format!("💥 {}", trunc(if c.impact.is_empty() { "impact" } else { &c.impact }, 10)));
        let k = labels.len().max(1);
        let mut prev: Option<(f64, f64)> = None;
        for (j, lab) in labels.iter().enumerate() {
            let x = (j as f64 + 0.5) / k as f64 * W;
            nodes.push(GNode { label: lab.clone(), x, y, color, highlight: j == 0 });
            if let Some((px, py)) = prev {
                edges.push(GEdge { x1: px, y1: py, x2: x, y2: y, color });
            }
            prev = Some((x, y));
        }
    }
    GraphLayout { nodes, edges, empty_msg: None }
}
