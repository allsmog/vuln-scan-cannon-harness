//! Threat-model-as-plan (#4) — turn the repo trust-graph into ranked proposals.
//!
//! Each high-value sink reachable from an untrusted entry becomes a
//! reachability-driven deep-scan; each datastore becomes an attacker-goal salvo.
//! Budget follows asset value: the untrusted→DB flow gets a proposal, the dead
//! corner doesn't. Falls back to the narrative threat model's components +
//! trust boundaries when no graph was built (`cannon map`).
//!
//! `graph_proposals` is pure and unit-tested over a synthetic graph.

use crate::artifacts::ThreatModel;
use crate::config::TargetConfig;
use crate::queue::{Proposal, ProposalSpec};
use crate::repomap::{RepoGraph, RepoNode};

fn asset_weight(kind: &str) -> f64 {
    match kind {
        "datastore" => 1.0,
        "sink" => 0.8,
        "external" => 0.7,
        "function" => 0.4,
        "route" | "entrypoint" => 0.35,
        _ => 0.3,
    }
}

fn loc(n: &RepoNode) -> String {
    let l = n.loc();
    if l.is_empty() {
        "location unknown".to_string()
    } else {
        l
    }
}

/// Proposals from a built trust-graph (pure). Two kinds: untrusted→sink flow
/// audits (ranked by asset value) and per-datastore attacker goals.
pub fn graph_proposals(graph: &RepoGraph) -> Vec<Proposal> {
    let mut props = Vec::new();
    if graph.is_empty() {
        return props;
    }

    for node in &graph.nodes {
        if !matches!(node.kind.as_str(), "sink" | "datastore" | "external") {
            continue;
        }
        if let Some(path) = graph.reachable_from_untrusted(&node.id) {
            let w = asset_weight(&node.kind);
            let focus = format!(
                "REACHABILITY-DRIVEN DEEP SCAN. The trust-graph shows an untrusted entry point reaches `{}` ({}) via: {}. Audit EVERY hop on this path for injection, missing authorization, and unsafe handling of the attacker-controlled value as it flows into this {}.{}",
                node.id,
                loc(node),
                path.join(" → "),
                node.kind,
                if node.note.is_empty() { String::new() } else { format!(" Context: {}.", node.note) },
            );
            props.push(Proposal::new(
                "threat-model",
                format!("Audit untrusted→{} flow into {}", node.kind, node.id),
                format!("{} is reachable from an untrusted entry across {} hop(s) — a high-value sink.", node.id, path.len().saturating_sub(1)),
                ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
                0.9 * w,
            ));
        }
    }

    for node in graph.nodes.iter().filter(|n| n.kind == "datastore") {
        let focus = format!(
            "ATTACKER GOAL — exfiltrate or tamper with `{}` ({}). Work backward from this datastore: what attacker-reachable path could read, modify, or dump it? Chain whatever auth gaps, injection, or SSRF gets you there, and report the path.",
            node.id,
            loc(node),
        );
        props.push(Proposal::new(
            "threat-model",
            format!("Attacker goal: reach datastore {}", node.id),
            "A datastore is a crown-jewel objective — permute toward reaching it.",
            ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
            0.82,
        ));
    }

    props
}

/// Fallback proposals from the narrative threat model when no graph exists.
fn narrative_proposals(tm: &ThreatModel) -> Vec<Proposal> {
    let mut props = Vec::new();
    for c in tm.components.iter().filter(|c| c.trust.to_lowercase().contains("untrusted")) {
        let focus = format!(
            "Untrusted-input component from the threat model: {} ({}). Audit everything it can reach for injection, authz gaps, and unsafe input handling.",
            c.name,
            if c.description.is_empty() { "no description" } else { &c.description }
        );
        props.push(Proposal::new(
            "threat-model",
            format!("Audit untrusted component: {}", c.name),
            "Threat-model component tagged untrusted-input.",
            ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
            0.6,
        ));
    }
    for b in tm.boundaries.iter().take(5) {
        let focus = format!("Trust-boundary crossing from the threat model: {b}. Audit the code that enforces (or fails to enforce) this boundary.");
        props.push(Proposal::new(
            "threat-model",
            format!("Audit trust boundary: {}", b.chars().take(40).collect::<String>()),
            "A trust boundary is where authz/validation must hold.",
            ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
            0.55,
        ));
    }
    props
}

/// Load the trust-graph (preferred) or threat-model narrative and emit proposals.
pub fn propose(target: &TargetConfig, max: usize) -> Vec<Proposal> {
    let mut props = match RepoGraph::load(&target.target_dir) {
        Some(g) => graph_proposals(&g),
        None => Vec::new(),
    };
    if props.is_empty() {
        if let Some(tm) = std::fs::read_to_string(target.target_dir.join("threat_model.json")).ok().and_then(|s| serde_json::from_str::<ThreatModel>(&s).ok()) {
            props = narrative_proposals(&tm);
        }
    }
    props.sort_by(|a, b| b.yield_score.partial_cmp(&a.yield_score).unwrap_or(std::cmp::Ordering::Equal));
    props.truncate(max);
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repomap::{RepoEdge, RepoNode};

    fn n(id: &str, kind: &str, trust: &str, file: &str, line: Option<u32>) -> RepoNode {
        RepoNode { id: id.into(), kind: kind.into(), trust: trust.into(), file: file.into(), line, note: String::new() }
    }
    fn e(from: &str, to: &str) -> RepoEdge {
        RepoEdge { from: from.into(), to: to.into(), kind: "calls".into() }
    }

    #[test]
    fn graph_proposals_target_reachable_high_value_sinks() {
        let g = RepoGraph {
            nodes: vec![
                n("route:GET /search", "route", "untrusted", "app.py", Some(40)),
                n("fn:handle", "function", "trusted", "app.py", Some(55)),
                n("store:users_db", "datastore", "datastore", "db.py", Some(12)),
                n("sink:os.system", "sink", "trusted", "cron.py", Some(20)), // unreachable from untrusted
            ],
            edges: vec![e("route:GET /search", "fn:handle"), e("fn:handle", "store:users_db")],
        };
        let props = graph_proposals(&g);
        // a flow audit into the reachable datastore + an attacker-goal for it
        assert!(props.iter().any(|p| p.title.contains("untrusted→datastore flow into store:users_db")));
        assert!(props.iter().any(|p| p.title.contains("Attacker goal: reach datastore store:users_db")));
        // the unreachable os.system sink gets NO flow proposal
        assert!(!props.iter().any(|p| p.title.contains("os.system")));
        // the datastore flow (asset 1.0) outranks everything
        let top = props.iter().max_by(|a, b| a.yield_score.partial_cmp(&b.yield_score).unwrap()).unwrap();
        assert!(top.title.contains("store:users_db"));
    }

    #[test]
    fn empty_graph_yields_nothing() {
        assert!(graph_proposals(&RepoGraph::default()).is_empty());
    }
}
