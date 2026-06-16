//! Verify stage — the load-bearing component.
//!
//! Runs N independent skeptics per finding, each with a different LENS
//! (reachability / exploitability / mitigation), then takes a majority vote.
//! Each skeptic is framed as an adversary: findings are guilty until proven
//! innocent. Skeptics also report access level + preconditions + the
//! entry→sink reachability path, which feed derived severity.

use crate::agent::{parse_xml_tag, run_agent, AgentOpts, AgentResult};
use crate::artifacts::{derive_severity, AccumulatedFinding, Verdict, Votes};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use std::collections::BTreeMap;
use std::path::PathBuf;

const VERIFY_LENSES: [(&str, &str); 3] = [
    (
        "reachability",
        "LENS — REACHABILITY: Concentrate on whether attacker-controlled input can actually reach the \
sink from a real external entry point. Trace the call path. If you cannot establish a concrete path \
from untrusted input to the sink, lean FALSE_POSITIVE. EXCEPTION: exposure / configuration / \
secret-management findings (hardcoded secrets, sensitive data in logs, insecure defaults, missing \
TLS) have NO untrusted-input→sink path by nature — for those, judge whether the sensitive thing is \
genuinely exposed, and do NOT reject them merely for lacking an input path.",
    ),
    (
        "exploitability",
        "LENS — EXPLOITABILITY: Assume the sink is reachable. Concentrate on whether it is actually \
exploitable for real impact, and exactly what access and preconditions an attacker needs. A finding \
that needs unrealistic preconditions is weak. For exposure findings (e.g. a hardcoded secret), \
'exploitable' means the secret/data is real and usable by whoever can read it — not that there is an \
input-driven trigger.",
    ),
    (
        "mitigation",
        "LENS — MITIGATIONS: Hunt for anything that neutralizes this on EVERY path — input validation, \
a guard or permission check, framework auto-escaping, a type constraint, unreachable code. If a \
deployed control kills it, say FALSE_POSITIVE and name the control.",
    ),
];

fn safe_sig(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect()
}

fn parse_confidence(s: Option<String>) -> f64 {
    let s = match s {
        Some(x) => x.trim().trim_end_matches('%').to_string(),
        None => return 0.0,
    };
    match s.parse::<f64>() {
        Ok(v) if v > 1.0 => v / 100.0,
        Ok(v) => v,
        Err(_) => 0.0,
    }
}

fn norm_verdict(s: Option<String>) -> String {
    let s = match s {
        Some(x) => x.trim().to_uppercase(),
        None => return "UNCERTAIN".into(),
    };
    if s.starts_with("REAL") || s.contains("TRUE") || s.contains("CONFIRM") {
        "REAL".into()
    } else if s.contains("FALSE") || s.starts_with("FP") || s.contains("NOT A") || s.contains("NOT_A") {
        "FALSE_POSITIVE".into()
    } else {
        "UNCERTAIN".into()
    }
}

struct Vote {
    lens: String,
    verdict: String,
    confidence: f64,
    access_level: Option<String>,
    preconditions: Vec<String>,
    reachability: Option<String>,
    reasoning: String,
}

#[allow(clippy::too_many_arguments)]
async fn run_one_vote(
    target: &TargetConfig,
    acc: &AccumulatedFinding,
    model: &str,
    lens_idx: usize,
    calib: &str,
    graph: Option<&crate::repomap::RepoGraph>,
    transcript_path: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> (Vote, BTreeMap<String, String>, AgentResult) {
    let f = &acc.representative;
    let sys = build_system_prompt(target, "default").expect("system prompt");
    let (lens_name, lens_text) = VERIFY_LENSES[lens_idx % VERIFY_LENSES.len()];

    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), target.source_root.display().to_string());
    vars.insert("title".into(), f.title.clone());
    vars.insert("severity".into(), f.severity.clone());
    vars.insert("file".into(), f.file.clone());
    vars.insert("line".into(), f.line.map(|l| l.to_string()).unwrap_or_else(|| "unknown".into()));
    vars.insert("cwe".into(), f.cwe.clone().unwrap_or_else(|| "unspecified".into()));
    vars.insert("description".into(), f.description.clone());
    vars.insert("evidence".into(), f.evidence.clone());
    vars.insert("exploit_premise".into(), if f.exploit_premise.is_empty() { "(none stated)".into() } else { f.exploit_premise.clone() });
    vars.insert(
        "taint_path".into(),
        if f.taint_path.is_empty() && f.taint_status.is_none() { "(the finder did not record a resolved taint path)".into() } else { f.taint_block() },
    );
    vars.insert(
        "graph_reachability".into(),
        match graph {
            Some(g) => g.reachability_for_location(&f.file, f.line).describe(),
            None => "(no repository call-graph was built; judge reachability from the code)".into(),
        },
    );
    vars.insert("corroboration".into(), acc.corroboration.to_string());
    vars.insert(
        "known_false_positives".into(),
        if calib.is_empty() { "(no prior false positives recorded for this repository)".into() } else { calib.to_string() },
    );
    let verify = load_prompt("verify", Some(&target.target_dir), "default", &vars).expect("verify prompt");

    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    if target.context_dir().is_dir() {
        opts.add_dirs = vec![target.context_dir().display().to_string()];
    }
    opts.system_prompt = Some(format!("{}\n\n{}", sys.text, lens_text));
    opts.transcript_path = transcript_path;
    opts.progress_prefix = progress_prefix;

    let agent = run_agent(&verify.text, &opts).await;
    let text = agent.find_tagged_message("verdict");
    let preconditions: Vec<String> = parse_xml_tag(&text, "preconditions")
        .map(|p| {
            p.lines()
                .map(|l| l.trim_matches([' ', '-', '\t']).to_string())
                .filter(|l| !l.is_empty() && l.to_lowercase() != "none")
                .collect()
        })
        .unwrap_or_default();
    let vote = Vote {
        lens: lens_name.to_string(),
        verdict: norm_verdict(parse_xml_tag(&text, "verdict")),
        confidence: parse_confidence(parse_xml_tag(&text, "confidence")),
        access_level: parse_xml_tag(&text, "access_level"),
        preconditions,
        reachability: parse_xml_tag(&text, "reachability"),
        reasoning: parse_xml_tag(&text, "reasoning").unwrap_or_default(),
    };
    let mut shas = BTreeMap::new();
    shas.insert("system".into(), sys.sha256.clone());
    shas.insert("verify".into(), verify.sha256.clone());
    (vote, shas, agent)
}

pub async fn run_verify(
    target: &TargetConfig,
    acc: &AccumulatedFinding,
    model: &str,
    votes: usize,
    verify_dir: Option<PathBuf>,
    progress_prefix: Option<String>,
) -> anyhow::Result<(Verdict, BTreeMap<String, String>, AgentResult)> {
    let n = votes.max(1);
    // Per-repo calibration: prior false-positive patterns from the ledger.
    let calib = crate::ledger::Ledger::load(&target.target_dir, &target.name).calibration_block();
    // Reachability oracle: the repo trust-graph, if one was built (`cannon map`).
    let graph = crate::repomap::RepoGraph::load(&target.target_dir);
    let mut cast: Vec<Vote> = Vec::new();
    let mut shas = BTreeMap::new();
    let mut last_agent = AgentResult::default();

    // Sequential within a finding (findings are already verified in parallel upstream).
    for i in 0..n {
        let tp = verify_dir.as_ref().map(|d| d.join(format!("{}.v{i}.jsonl", safe_sig(&acc.signature))));
        let (vote, s, agent) = run_one_vote(target, acc, model, i, &calib, graph.as_ref(), tp, progress_prefix.clone()).await;
        shas = s;
        last_agent = agent;
        cast.push(vote);
    }

    // Tally.
    let real = cast.iter().filter(|v| v.verdict == "REAL").count();
    let fp = cast.iter().filter(|v| v.verdict == "FALSE_POSITIVE").count();
    let uncertain = n - real - fp;
    let majority = n / 2 + 1;
    let final_verdict = if real >= majority {
        "REAL"
    } else if fp >= majority {
        "FALSE_POSITIVE"
    } else {
        "UNCERTAIN"
    }
    .to_string();

    // Pick the most-confident vote on the winning side for the structured fields.
    let lead = cast
        .iter()
        .filter(|v| v.verdict == final_verdict)
        .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
        .or_else(|| cast.iter().max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)));

    let matching: Vec<&Vote> = cast.iter().filter(|v| v.verdict == final_verdict).collect();
    let confidence = if !matching.is_empty() {
        matching.iter().map(|v| v.confidence).sum::<f64>() / matching.len() as f64
    } else {
        cast.iter().map(|v| v.confidence).sum::<f64>() / n as f64
    };

    let access_level = lead.and_then(|v| v.access_level.clone()).or_else(|| cast.iter().find_map(|v| v.access_level.clone()));
    let preconditions = lead.map(|v| v.preconditions.clone()).unwrap_or_default();
    let reachability = lead.and_then(|v| v.reachability.clone());
    let derived = derive_severity(access_level.as_deref(), preconditions.len(), &acc.max_severity);

    let reasoning = cast
        .iter()
        .map(|v| format!("[{}:{}] {}", v.lens, v.verdict, v.reasoning.chars().take(220).collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n");

    let verdict = Verdict {
        signature: acc.signature.clone(),
        verdict: final_verdict,
        confidence,
        reasoning,
        access_level,
        preconditions,
        reachability,
        derived_severity: Some(derived),
        votes: Some(Votes {
            real,
            false_positive: fp,
            uncertain,
            lenses: cast.iter().map(|v| v.lens.clone()).collect(),
        }),
    };
    Ok((verdict, shas, last_agent))
}
