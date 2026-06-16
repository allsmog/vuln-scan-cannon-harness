//! Repo-map stage: an agent reads the whole target and emits a trust graph —
//! entrypoints/routes/functions/sinks/datastores as nodes (with a trust tier)
//! and calls/routes-to/reads/writes as edges. The result (`repo_map.json`) is the
//! reachability oracle consumed by the verifier (`repomap::RepoGraph`).

use crate::agent::{parse_all_tags, run_agent, AgentOpts, AgentResult};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use crate::repomap::{RepoEdge, RepoGraph, RepoNode};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn split_file_line(s: &str) -> (String, Option<u32>) {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return (String::new(), None);
    }
    if let Some((path, num)) = s.rsplit_once(':') {
        if let Ok(n) = num.trim().parse::<u32>() {
            return (path.trim().to_string(), Some(n));
        }
    }
    (s.to_string(), None)
}

fn parse_nodes(text: &str) -> Vec<RepoNode> {
    let mut out = Vec::new();
    for block in parse_all_tags(text, "node") {
        let p: Vec<String> = block.splitn(5, '|').map(|x| x.trim().to_string()).collect();
        if p.is_empty() || p[0].is_empty() {
            continue;
        }
        let (file, line) = p.get(3).map(|s| split_file_line(s)).unwrap_or_default();
        out.push(RepoNode {
            id: p[0].clone(),
            kind: p.get(1).cloned().unwrap_or_default().to_lowercase(),
            trust: p.get(2).cloned().unwrap_or_default().to_lowercase(),
            file,
            line,
            note: p.get(4).cloned().unwrap_or_default(),
        });
    }
    out
}

fn parse_edges(text: &str) -> Vec<RepoEdge> {
    let mut out = Vec::new();
    for block in parse_all_tags(text, "edge") {
        let (body, kind) = match block.split_once('|') {
            Some((b, k)) => (b.to_string(), k.trim().to_lowercase()),
            None => (block.clone(), String::new()),
        };
        if let Some((from, to)) = body.split_once("->") {
            let (from, to) = (from.trim(), to.trim());
            if !from.is_empty() && !to.is_empty() {
                out.push(RepoEdge { from: from.to_string(), to: to.to_string(), kind });
            }
        }
    }
    out
}

pub fn parse_graph(text: &str) -> RepoGraph {
    RepoGraph { nodes: parse_nodes(text), edges: parse_edges(text) }
}

pub async fn run_repomap(
    target: &TargetConfig,
    model: &str,
    context_block: &str,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<(RepoGraph, AgentResult)> {
    let sys = build_system_prompt(target, "default")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("language".into(), target.language.clone().unwrap_or_else(|| "unspecified".into()));
    vars.insert("description".into(), target.description.clone().unwrap_or_else(|| "(no description provided)".into()));
    vars.insert(
        "context".into(),
        if context_block.is_empty() { "(no project context documents were provided)".into() } else { context_block.to_string() },
    );
    let prompt = load_prompt("repo_map", Some(&target.target_dir), "default", &vars)?;

    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix;

    let agent = run_agent(&prompt.text, &opts).await;
    let graph = parse_graph(&agent.all_text());
    Ok((graph, agent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nodes_and_edges() {
        let text = "
blah blah
<node>route:GET /ping | route | untrusted | app.py:40 | ping handler</node>
<node>fn:do_ping | function | trusted | app.py:55 | handler body</node>
<node>sink:os.system | sink | trusted | util.py:9 | shells out</node>
<edge>route:GET /ping -> fn:do_ping | routes_to</edge>
<edge>fn:do_ping -> sink:os.system | calls</edge>
";
        let g = parse_graph(text);
        assert_eq!(g.nodes.len(), 3);
        assert_eq!(g.edges.len(), 2);
        assert_eq!(g.nodes[0].id, "route:GET /ping");
        assert_eq!(g.nodes[0].trust, "untrusted");
        assert_eq!(g.nodes[0].line, Some(40));
        assert_eq!(g.edges[1].from, "fn:do_ping");
        assert_eq!(g.edges[1].to, "sink:os.system");
        // the graph is usable end-to-end
        assert!(g.reachable_from_untrusted("sink:os.system").is_some());
    }
}
