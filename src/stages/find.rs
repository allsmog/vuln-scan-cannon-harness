//! Find stage: one find-agent reads the target source (scoped by focus area)
//! and emits structured <finding> blocks. Read-only, no execution.

use crate::agent::{parse_all_tags, parse_xml_tag, run_agent, AgentOpts, AgentResult};
use crate::artifacts::{norm_severity, norm_taint_status, Finding, TaintStep};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::permute::Spec;
use crate::prompts::load_prompt;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

fn parse_line(s: Option<String>) -> Option<u32> {
    let s = s?;
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn norm_role(s: &str) -> String {
    let t = s.trim().to_lowercase();
    for canon in ["source", "propagator", "sanitizer", "sink", "constant"] {
        if t.contains(canon) {
            return canon.to_string();
        }
    }
    if t.contains("entry") || t.contains("input") {
        "source".into()
    } else if t.contains("flow") || t.contains("pass") || t.contains("call") {
        "propagator".into()
    } else {
        t
    }
}

/// Split "path/to/file.ext:123" into (path, Some(123)); tolerate a missing line.
fn split_file_line(s: &str) -> (String, Option<u32>) {
    let s = s.trim();
    if let Some((path, num)) = s.rsplit_once(':') {
        if let Ok(n) = num.trim().parse::<u32>() {
            return (path.trim().to_string(), Some(n));
        }
    }
    (s.to_string(), None)
}

/// Parse a `<taint_path>` body: one hop per line, `role | file:line | note`.
fn parse_taint_path(block: &str) -> Vec<TaintStep> {
    let mut out = Vec::new();
    for line in block.lines() {
        let line = line.trim().trim_start_matches(['-', '*', ' ']);
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '|').map(|p| p.trim()).collect();
        if parts.len() < 2 {
            continue;
        }
        let (file, ln) = split_file_line(parts[1]);
        if file.is_empty() {
            continue;
        }
        out.push(TaintStep {
            role: norm_role(parts[0]),
            file,
            line: ln,
            note: parts.get(2).map(|s| s.to_string()).unwrap_or_default(),
        });
    }
    out
}

fn parse_finding_block(block: &str, spec: &Spec) -> Option<Finding> {
    let title = parse_xml_tag(block, "title")?;
    let file = parse_xml_tag(block, "file")?;
    if title.is_empty() || file.is_empty() {
        return None;
    }
    Some(Finding {
        title,
        severity: norm_severity(&parse_xml_tag(block, "severity").unwrap_or_default()),
        file,
        line: parse_line(parse_xml_tag(block, "line")),
        cwe: parse_xml_tag(block, "cwe"),
        description: parse_xml_tag(block, "description").unwrap_or_default(),
        evidence: parse_xml_tag(block, "evidence").unwrap_or_default(),
        exploit_premise: parse_xml_tag(block, "exploit_premise").unwrap_or_default(),
        focus_area: spec.focus_area.clone(),
        round_label: Some(spec.label.clone()),
        taint_path: parse_xml_tag(block, "taint_path").map(|b| parse_taint_path(&b)).unwrap_or_default(),
        taint_status: parse_xml_tag(block, "taint_status").and_then(|s| norm_taint_status(&s)),
    })
}

pub struct FindOutput {
    pub findings: Vec<Finding>,
    pub prompt_shas: BTreeMap<String, String>,
    pub prompt_sources: BTreeMap<String, String>,
    pub agent: AgentResult,
    pub elapsed: f64,
    /// candidate findings the finder's own taint trace disproved (constant /
    /// sanitized / unreachable) and which were therefore dropped.
    pub self_refuted: usize,
}

pub async fn run_find(
    target: &TargetConfig,
    spec: &Spec,
    context_block: &str,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<FindOutput> {
    let sys = build_system_prompt(target, &spec.variant)?;

    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("language".into(), target.language.clone().unwrap_or_else(|| "unspecified".into()));
    vars.insert(
        "focus_area".into(),
        spec.focus_area.clone().unwrap_or_else(|| "the entire codebase (no specific focus area assigned)".into()),
    );
    vars.insert(
        "context".into(),
        if context_block.is_empty() { "(no project context documents were provided)".into() } else { context_block.to_string() },
    );
    let find = load_prompt("find", Some(&target.target_dir), &spec.variant, &vars)?;

    let mut opts = AgentOpts::new(&spec.model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix.clone();

    let t0 = Instant::now();
    let agent = run_agent(&find.text, &opts).await;
    let elapsed = t0.elapsed().as_secs_f64();

    // Interprocedural taint resolution: keep only findings the finder did NOT
    // disprove with its own cross-file trace. A `constant` / `sanitized` /
    // `not_reachable` outcome means the finder followed the data and found the
    // bug doesn't hold (e.g. a helper in another file returns a constant) — drop
    // it. Recall-safe: `reachable` / `exposure` / `unresolved` / unrecorded pass.
    let mut findings = Vec::new();
    let mut self_refuted = 0usize;
    for block in parse_all_tags(&agent.all_text(), "finding") {
        if let Some(f) = parse_finding_block(&block, spec) {
            if f.taint_self_refuted() {
                self_refuted += 1;
            } else {
                findings.push(f);
            }
        }
    }
    if self_refuted > 0 {
        eprintln!(
            "{}",
            crate::ui::ecolor(
                &format!("{}   ⏚ dropped {self_refuted} self-refuted finding(s) (finder traced taint to a constant / sanitizer / dead end)", progress_prefix.as_deref().unwrap_or("")),
                "dim",
            )
        );
    }

    let mut shas = BTreeMap::new();
    shas.insert("system".into(), sys.sha256.clone());
    shas.insert("find".into(), find.sha256.clone());
    let mut sources = BTreeMap::new();
    sources.insert("system".into(), sys.source.clone());
    sources.insert("find".into(), find.source.clone());

    Ok(FindOutput { findings, prompt_shas: shas, prompt_sources: sources, agent, elapsed, self_refuted })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec { round_idx: 0, label: "r00".into(), focus_area: None, variant: "default".into(), model: "m".into() }
    }

    #[test]
    fn split_file_line_parses_trailing_number() {
        assert_eq!(split_file_line("src/app.py:42"), ("src/app.py".into(), Some(42)));
        assert_eq!(split_file_line("src/app.py"), ("src/app.py".into(), None));
        assert_eq!(split_file_line("Helper.java:7  "), ("Helper.java".into(), Some(7)));
    }

    #[test]
    fn parse_taint_path_reads_role_file_note() {
        let body = "\nsource | helpers/Req.java:10 | request param\n- propagator | Svc.java:20 | passed to query\nsink | App.java:30 | executeQuery\n";
        let steps = parse_taint_path(body);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].role, "source");
        assert_eq!(steps[0].file, "helpers/Req.java");
        assert_eq!(steps[0].line, Some(10));
        assert_eq!(steps[2].role, "sink");
        assert_eq!(steps[1].note, "passed to query");
    }

    #[test]
    fn finding_block_carries_taint_and_status() {
        let block = "<title>SQLi</title><file>App.java</file><line>30</line>\
<taint_status>constant</taint_status>\
<taint_path>source | Req.java:10 | getTheValue returns \"bar\"\nsink | App.java:30 | executeQuery</taint_path>";
        let f = parse_finding_block(block, &spec()).unwrap();
        assert_eq!(f.taint_status.as_deref(), Some("constant"));
        assert_eq!(f.taint_path.len(), 2);
        // the finder disproved its own report → it must be dropped
        assert!(f.taint_self_refuted());
    }

    #[test]
    fn reachable_finding_is_kept() {
        let block = "<title>SQLi</title><file>App.java</file><line>30</line>\
<taint_status>reachable</taint_status>\
<taint_path>source | Req.java:10 | request param\nsink | App.java:30 | executeQuery</taint_path>";
        let f = parse_finding_block(block, &spec()).unwrap();
        assert!(!f.taint_self_refuted());
        assert!(f.taint_grounded());
    }
}
