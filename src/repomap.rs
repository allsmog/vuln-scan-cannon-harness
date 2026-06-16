//! Repo-scale trust graph — a call / route / trust map of the whole target,
//! built once and then used as a reachability ORACLE during verification.
//!
//! Where the threat model is a human picture, this is machine data the verifier
//! consults: "is this sink reachable from an untrusted entry point, following
//! the actual call edges?" The reachability search here is pure and deterministic
//! (and unit-tested); only the graph *construction* (in `stages/repomap.rs`) uses
//! an agent.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

/// A vertex: an entrypoint, route, function, sink, datastore, or external system.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoNode {
    /// stable key, e.g. `route:GET /ping`, `fn:app.handle`, `sink:os.system`
    pub id: String,
    /// entrypoint | route | function | sink | datastore | external
    #[serde(default)]
    pub kind: String,
    /// untrusted | boundary | trusted | datastore | external
    #[serde(default)]
    pub trust: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub note: String,
}

/// A directed edge: who calls / routes-to / reads / writes whom.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoEdge {
    pub from: String,
    pub to: String,
    /// calls | routes_to | reads | writes | flows
    #[serde(default)]
    pub kind: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RepoGraph {
    #[serde(default)]
    pub nodes: Vec<RepoNode>,
    #[serde(default)]
    pub edges: Vec<RepoEdge>,
}

impl RepoNode {
    pub fn loc(&self) -> String {
        match self.line {
            Some(l) if !self.file.is_empty() => format!("{}:{}", self.file, l),
            _ => self.file.clone(),
        }
    }
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

/// The verdict of a reachability query, shaped for the verifier prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphReachability {
    /// a graph node matched the finding's location
    pub found: bool,
    /// that node is reachable from some untrusted entry point
    pub reachable: bool,
    pub node_id: Option<String>,
    /// ids from the untrusted entry through to the node (when reachable)
    pub path: Vec<String>,
}

impl GraphReachability {
    fn none() -> Self {
        GraphReachability { found: false, reachable: false, node_id: None, path: Vec::new() }
    }

    /// A sentence the verifier can weigh. Deliberately hedged: the graph is an
    /// oracle, not ground truth — the verifier still judges the code.
    pub fn describe(&self) -> String {
        if !self.found {
            return "the static call-graph has no node at this location (inconclusive — judge from the code).".into();
        }
        if self.reachable {
            format!(
                "the static call-graph DOES connect an untrusted entry point to this location: {}.",
                self.path.join(" → ")
            )
        } else {
            format!(
                "the static call-graph finds NO path from any untrusted entry point to this location (node `{}`) — a strong signal it is unreachable, but confirm against the code.",
                self.node_id.clone().unwrap_or_default()
            )
        }
    }
}

impl RepoGraph {
    pub fn json_path(target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(".cannon").join("repo_map.json")
    }

    /// Load the persisted graph for a target, if one was built.
    pub fn load(target_dir: &Path) -> Option<RepoGraph> {
        let s = std::fs::read_to_string(Self::json_path(target_dir)).ok()?;
        let g: RepoGraph = serde_json::from_str(&s).ok()?;
        if g.nodes.is_empty() { None } else { Some(g) }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn node(&self, id: &str) -> Option<&RepoNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// A node an external/unauthenticated actor can drive directly.
    fn is_untrusted_entry(n: &RepoNode) -> bool {
        let t = n.trust.to_lowercase();
        t.contains("untrusted") || t.contains("external") || n.kind.eq_ignore_ascii_case("entrypoint")
    }

    pub fn untrusted_entries(&self) -> Vec<&RepoNode> {
        self.nodes.iter().filter(|n| Self::is_untrusted_entry(n)).collect()
    }

    fn adjacency(&self) -> BTreeMap<&str, Vec<&str>> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for e in &self.edges {
            adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
        }
        adj
    }

    /// Forward multi-source BFS from every untrusted entry. Returns the shortest
    /// id-path to `target_id` if one exists, else None.
    pub fn reachable_from_untrusted(&self, target_id: &str) -> Option<Vec<String>> {
        if self.node(target_id).is_none() {
            return None;
        }
        let adj = self.adjacency();
        let mut prev: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen: BTreeMap<&str, bool> = BTreeMap::new();
        let mut q: VecDeque<&str> = VecDeque::new();
        for entry in self.untrusted_entries() {
            if seen.insert(entry.id.as_str(), true).is_none() {
                q.push_back(entry.id.as_str());
            }
        }
        if seen.contains_key(target_id) {
            return Some(vec![target_id.to_string()]); // the entry itself is the sink
        }
        while let Some(cur) = q.pop_front() {
            if let Some(nexts) = adj.get(cur) {
                for &nx in nexts {
                    if seen.insert(nx, true).is_none() {
                        prev.insert(nx, cur);
                        if nx == target_id {
                            // reconstruct
                            let mut path = vec![nx];
                            let mut c = nx;
                            while let Some(&p) = prev.get(c) {
                                path.push(p);
                                c = p;
                            }
                            path.reverse();
                            return Some(path.into_iter().map(|s| s.to_string()).collect());
                        }
                        q.push_back(nx);
                    }
                }
            }
        }
        None
    }

    /// Find the graph node best matching a finding's `file:line` — basename match,
    /// then nearest line. Returns None when nothing in the graph is close.
    pub fn node_for_location(&self, file: &str, line: Option<u32>) -> Option<&RepoNode> {
        let want = basename(file);
        let candidates: Vec<&RepoNode> = self.nodes.iter().filter(|n| !n.file.is_empty() && basename(&n.file) == want).collect();
        if candidates.is_empty() {
            return None;
        }
        match line {
            Some(l) => candidates
                .into_iter()
                .min_by_key(|n| n.line.map(|nl| (nl as i64 - l as i64).unsigned_abs()).unwrap_or(u64::MAX)),
            None => Some(candidates[0]),
        }
    }

    /// The oracle query the verifier uses: map a finding location to a node, then
    /// ask whether that node is reachable from any untrusted entry.
    pub fn reachability_for_location(&self, file: &str, line: Option<u32>) -> GraphReachability {
        let node = match self.node_for_location(file, line) {
            Some(n) => n,
            None => return GraphReachability::none(),
        };
        match self.reachable_from_untrusted(&node.id) {
            Some(path) => GraphReachability { found: true, reachable: true, node_id: Some(node.id.clone()), path },
            None => GraphReachability { found: true, reachable: false, node_id: Some(node.id.clone()), path: Vec::new() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: &str, kind: &str, trust: &str, file: &str, line: Option<u32>) -> RepoNode {
        RepoNode { id: id.into(), kind: kind.into(), trust: trust.into(), file: file.into(), line, note: String::new() }
    }
    fn e(from: &str, to: &str) -> RepoEdge {
        RepoEdge { from: from.into(), to: to.into(), kind: "calls".into() }
    }

    fn graph() -> RepoGraph {
        // untrusted route → handler → query sink ;  internal cron → other sink (no untrusted path)
        RepoGraph {
            nodes: vec![
                n("route:GET /search", "route", "untrusted", "app.py", Some(40)),
                n("fn:handle_search", "function", "trusted", "app.py", Some(55)),
                n("sink:db.query", "sink", "datastore", "db.py", Some(12)),
                n("fn:nightly_cron", "function", "trusted", "cron.py", Some(3)),
                n("sink:os.system", "sink", "trusted", "cron.py", Some(20)),
            ],
            edges: vec![
                e("route:GET /search", "fn:handle_search"),
                e("fn:handle_search", "sink:db.query"),
                e("fn:nightly_cron", "sink:os.system"),
            ],
        }
    }

    #[test]
    fn reachable_sink_has_path_from_untrusted() {
        let g = graph();
        let path = g.reachable_from_untrusted("sink:db.query").expect("reachable");
        assert_eq!(path, vec!["route:GET /search", "fn:handle_search", "sink:db.query"]);
    }

    #[test]
    fn internal_only_sink_is_not_reachable() {
        let g = graph();
        // os.system is only reached by the cron (trusted), not from any untrusted entry
        assert!(g.reachable_from_untrusted("sink:os.system").is_none());
    }

    #[test]
    fn unknown_node_is_not_reachable() {
        assert!(graph().reachable_from_untrusted("sink:nope").is_none());
    }

    #[test]
    fn node_for_location_matches_basename_and_nearest_line() {
        let g = graph();
        // a finding reported at db.py:14 → nearest node is db.query at line 12
        let node = g.node_for_location("targets/x/src/db.py", Some(14)).unwrap();
        assert_eq!(node.id, "sink:db.query");
    }

    #[test]
    fn reachability_for_location_end_to_end() {
        let g = graph();
        let r = g.reachability_for_location("db.py", Some(12));
        assert!(r.found && r.reachable);
        assert!(r.describe().contains("untrusted entry point to this location"));

        let r2 = g.reachability_for_location("cron.py", Some(20));
        assert!(r2.found && !r2.reachable);
        assert!(r2.describe().contains("NO path"));

        let r3 = g.reachability_for_location("unknown.py", Some(1));
        assert!(!r3.found);
        assert!(r3.describe().contains("no node"));
    }
}
