//! cannon — fire salvos of permuted scans at a target, then accumulate,
//! triage, attack-chain, and visualize (in a Ratatui cockpit).

mod agent;
mod artifacts;
mod bench;
mod config;
mod context;
mod detector;
mod dynamic;
mod fleet;
mod framing;
mod ledger;
mod lock;
mod metamorphic;
mod generators;
mod permute;
mod prompts;
mod queue;
mod repomap;
mod runner;
mod sarif;
mod secrets;
mod seed;
mod stages;
mod tune;
mod tui;
mod ui;
mod viz;

use anyhow::{Context, Result};
use artifacts::{accumulate, triage, AccumulatedFinding, Chain, ThreatModel, TriagedFinding, Verdict};
use clap::{Parser, Subcommand};
use config::TargetConfig;
use context::load_full_context;
use ledger::Ledger;
use permute::{build_matrix, Spec};
use stages::chain::ChainCandidate;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use ui::color;

fn targets_root() -> String {
    std::env::var("CANNON_TARGETS").unwrap_or_else(|_| "targets".to_string())
}
fn results_root() -> String {
    std::env::var("CANNON_RESULTS").unwrap_or_else(|_| "results".to_string())
}
fn resolve_model(m: Option<String>) -> String {
    m.or_else(|| std::env::var("CANNON_MODEL").ok()).unwrap_or_else(|| "opus".to_string())
}

fn new_results_dir(target_name: &str) -> Result<PathBuf> {
    // Timestamp is second-precision, so two runs started in the same second
    // would share a dir and overwrite each other's `run_NNN/result.json`.
    // `create_dir` is atomic "create iff absent"; on collision append `-NNN`
    // until one wins, guaranteeing every run gets its own directory.
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let base = PathBuf::from(results_root()).join(target_name);
    std::fs::create_dir_all(&base)?;
    for n in 0..10_000 {
        let d = if n == 0 { base.join(&ts) } else { base.join(format!("{ts}-{n:03}")) };
        match std::fs::create_dir(&d) {
            Ok(()) => return Ok(d),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("could not allocate a unique results dir under {}", base.display())
}

fn csv(s: &Option<String>) -> Vec<String> {
    s.as_ref()
        .map(|x| x.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default()
}

fn target_from_results(results_dir: &str) -> Option<String> {
    Path::new(results_dir)
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
}

// ──────────────────────────────────────────────────────────────────────────────
// CLI
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "cannon", about = "AI security harness — aim → fire → triage → manage → prove → chain → fix → measure.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// AIM · threat-model the target + seed focus areas (+ Mermaid graph)
    #[command(aliases = ["threat-model", "recon"])]
    Aim {
        target: String,
        #[arg(long)]
        model: Option<String>,
    },
    /// AIM · build the repo trust-graph (reachability oracle for the verifier)
    Map {
        target: String,
        #[arg(long)]
        model: Option<String>,
    },
    /// PLAN · signal-driven, human-gated permutation — propose → approve → fire
    Permute {
        target: String,
        #[arg(long)]
        model: Option<String>,
        /// signals to mine (comma-sep): commits,threat-model,threat-intel,evolution
        #[arg(long)]
        sources: Option<String>,
        /// max proposals per signal
        #[arg(long, default_value_t = 6)]
        max: usize,
        /// hard cost cap ($) on the queue
        #[arg(long)]
        budget: Option<f64>,
        /// also research live CVEs for the detected stack (web)
        #[arg(long)]
        research: bool,
        /// non-interactive: auto-approve every proposal that fits under the cap
        #[arg(long)]
        yes: bool,
        /// only queue the proposals; fire later with `cannon queue run`
        #[arg(long = "plan-only")]
        plan_only: bool,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// PLAN · inspect / run / clear the permutation queue
    Queue {
        #[command(subcommand)]
        sub: QueueCmd,
    },
    /// FIRE · salvo of permuted scans → accumulate → triage → ledger
    Fire {
        target: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 1)]
        runs: usize,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        #[arg(long)]
        focus: Option<String>,
        #[arg(long)]
        variants: Option<String>,
        #[arg(long)]
        models: Option<String>,
        #[arg(long = "threat-model")]
        threat_model: bool,
        #[arg(long)]
        recon: bool,
        #[arg(long)]
        chain: bool,
        /// semantic dedup pass (LLM judge collapses cross-location duplicates)
        #[arg(long)]
        dedup: bool,
        /// build the repo trust-graph first; the verifier uses it as a reachability oracle
        #[arg(long = "repo-map")]
        repo_map: bool,
        /// override the target's detector (static_review | secrets | dynamic)
        #[arg(long = "detector")]
        detector: Option<String>,
        #[arg(long = "verify-top", default_value_t = 0)]
        verify_top: usize,
        /// independent adversarial verifier votes per finding (majority wins)
        #[arg(long, default_value_t = DEFAULT_VOTES)]
        votes: usize,
        /// scope the salvo to files changed since this git ref (PR/diff review)
        #[arg(long)]
        diff: Option<String>,
        #[arg(long)]
        resume: Option<String>,
    },
    /// TRIAGE · adversarially (re)verify the ledger's findings (incl. seeded backlog)
    #[command(alias = "verify")]
    Triage {
        target: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// re-verify everything, not just unverified findings
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = DEFAULT_VOTES)]
        votes: usize,
    },
    /// MANAGE · open the cockpit to browse & triage findings
    #[command(alias = "tui")]
    Manage { target: String, #[arg(long)] model: Option<String> },
    /// MANAGE · list / set status / sync the findings ledger
    Findings {
        #[command(subcommand)]
        sub: FindingsCmd,
    },
    /// MANAGE · import existing scanner output (SARIF / Semgrep / JSON / CSV)
    Seed {
        target: String,
        /// one or more scanner-output files
        files: Vec<String>,
        #[arg(long, default_value = "auto")]
        format: String,
        /// immediately run the verifier over the newly-seeded findings
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// MANAGE · merge an existing run's triage.json into the ledger
    Ingest { target: String, results_dir: String },
    /// PROVE · run the dynamic detector — reproduce findings by execution (needs CANNON_ALLOW_EXEC=1)
    Prove {
        target: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 2)]
        concurrency: usize,
        #[arg(long, default_value_t = DEFAULT_VOTES)]
        votes: usize,
    },
    /// PROVE · metamorphic check — perturb the code to prove safe-vs-vulnerable
    Metamorphic {
        target: String,
        #[arg(long)]
        model: Option<String>,
        /// a single finding id (default: every confirmed + uncertain finding)
        #[arg(long)]
        id: Option<String>,
        /// confirmed | uncertain | review (confirmed+uncertain) | all
        #[arg(long, default_value = "review")]
        scope: String,
        #[arg(long, default_value_t = 2)]
        concurrency: usize,
        /// write the metamorphic verdict back to the ledger (non-human findings only)
        #[arg(long)]
        apply: bool,
    },
    /// CHAIN · compose attack chains from confirmed findings
    Chain {
        target: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = "confirmed")]
        scope: String,
    },
    /// CHAIN · scan a fleet -> cross-service attack chains
    Fleet {
        fleet: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        #[arg(long, default_value_t = DEFAULT_VOTES)]
        votes: usize,
    },
    /// FIX · draft patches + independent review (never applied)
    #[command(alias = "patch")]
    Fix {
        target: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = "confirmed")]
        scope: String,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// only patch the top-N by severity (0 = all)
        #[arg(long, default_value_t = 0)]
        top: usize,
    },
    /// MEASURE · score against a labeled corpus (precision / recall / F1)
    #[command(alias = "bench")]
    Measure {
        corpus: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// run the full pipeline (verify) instead of scoring the detector's raw findings
        #[arg(long)]
        verify: bool,
        #[arg(long, default_value_t = DEFAULT_VOTES)]
        votes: usize,
        /// line-match tolerance
        #[arg(long, default_value_t = 3)]
        tol: u32,
        /// score an external tool's SARIF against the corpus labels (e.g. semgrep)
        #[arg(long)]
        against: Option<String>,
        /// fail (exit 2) if F1 regressed below the pinned baseline
        #[arg(long)]
        gate: bool,
        /// pin the current F1 as the regression baseline
        #[arg(long = "write-baseline")]
        write_baseline: bool,
    },
    /// MEASURE · tune prompts against labeled ground truth (train/test split)
    Tune {
        corpus: String,
        #[arg(long)]
        model: Option<String>,
        /// prompt variants to compare (comma-separated), e.g. default,aggressive
        #[arg(long)]
        variants: Option<String>,
        #[arg(long)]
        verify: bool,
        #[arg(long, default_value_t = DEFAULT_VOTES)]
        votes: usize,
        #[arg(long, default_value_t = 3)]
        tol: u32,
        /// fraction of the corpus held out for the generalization check
        #[arg(long, default_value_t = 0.5)]
        holdout: f64,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// OUTPUT · re-render REPORT.md from a results dir
    Report { results_dir: String },
}

#[derive(Subcommand)]
enum FindingsCmd {
    List { target: String },
    Show { target: String, id: String },
    Set {
        target: String,
        id: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        note: Option<String>,
    },
    Sync { target: String },
}

#[derive(Subcommand)]
enum QueueCmd {
    /// show every proposal (status, est cost, yield, outcome)
    List { target: String },
    /// fire all approved proposals (deferred execution)
    Run {
        target: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// drop decided (done/skipped/failed) proposals, keep the live queue
    Clear { target: String },
    /// set (or, with 0, clear) the queue-wide cost cap
    Budget { target: String, cap: f64 },
}

// ──────────────────────────────────────────────────────────────────────────────
// shared: adversarial verify of accumulated findings
// ──────────────────────────────────────────────────────────────────────────────

const DEFAULT_VOTES: usize = 3;

#[allow(clippy::too_many_arguments)]
async fn verify_all(
    target: &TargetConfig,
    accumulated: &[AccumulatedFinding],
    model: &str,
    results_dir: &Path,
    concurrency: usize,
    top: usize,
    votes: usize,
) -> BTreeMap<String, Verdict> {
    let items: Vec<AccumulatedFinding> = if top > 0 {
        accumulated.iter().take(top).cloned().collect()
    } else {
        accumulated.to_vec()
    };
    verify_items(target, items, model, results_dir.join("verify"), concurrency, votes).await
}

/// Adversarially verify a set of findings concurrently (N lensed votes each).
async fn verify_items(
    target: &TargetConfig,
    items: Vec<AccumulatedFinding>,
    model: &str,
    verify_dir: PathBuf,
    concurrency: usize,
    votes: usize,
) -> BTreeMap<String, Verdict> {
    std::fs::create_dir_all(&verify_dir).ok();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let target = Arc::new(target.clone());
    let model = model.to_string();
    let mut set: JoinSet<(String, Verdict)> = JoinSet::new();

    for acc in items {
        let sem = sem.clone();
        let target = target.clone();
        let model = model.clone();
        let verify_dir = verify_dir.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            println!(
                "{}",
                color(
                    &format!("  ⚖ verifying {} {} (×{})", acc.max_severity, acc.representative.title.chars().take(60).collect::<String>(), acc.corroboration),
                    "verify"
                )
            );
            let prefix = format!("  [verify {}]", acc.signature.chars().take(18).collect::<String>());
            let verdict = match stages::verify::run_verify(&target, &acc, &model, votes, Some(verify_dir.clone()), Some(prefix)).await {
                Ok((v, _, _)) => v,
                Err(e) => Verdict { signature: acc.signature.clone(), verdict: "UNCERTAIN".into(), confidence: 0.0, reasoning: format!("verify error: {e}"), ..Default::default() },
            };
            let mark = match verdict.verdict.as_str() { "REAL" => "✅", "FALSE_POSITIVE" => "❌", _ => "❔" };
            let tally = verdict.votes.as_ref().map(|v| format!(" [{}R/{}F/{}U]", v.real, v.false_positive, v.uncertain)).unwrap_or_default();
            let sev = verdict.derived_severity.clone().unwrap_or_default();
            println!("    {mark} {}{} ({:.2}) sev~{}", verdict.verdict, tally, verdict.confidence, sev);
            (acc.signature.clone(), verdict)
        });
    }

    let mut verdicts = BTreeMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok((sig, v)) = res {
            verdicts.insert(sig, v);
        }
    }
    verdicts
}

fn ledger_to_candidates(findings: &[&ledger::LedgerFinding]) -> Vec<ChainCandidate> {
    findings
        .iter()
        .map(|f| ChainCandidate {
            signature: f.signature.clone(),
            title: f.title.clone(),
            loc: f.loc(),
            severity: f.severity.clone(),
            premise: f.exploit_premise.clone(),
            description: f.description.clone(),
        })
        .collect()
}

fn final_summary(results_dir: &Path, triaged: &[TriagedFinding], chains: &[Chain]) {
    let confirmed: Vec<&TriagedFinding> = triaged.iter().filter(|t| t.confirmed()).collect();
    println!("{}", color("\n  ── salvo complete ─────────────────────────────", "cannon"));
    println!("  unique findings : {}", triaged.len());
    println!("  confirmed       : {}", color(&confirmed.len().to_string(), "bold"));
    println!("  attack chains   : {}", chains.len());
    println!("  report          : {}", color(&results_dir.join("REPORT.md").display().to_string(), "report"));
    let (it, ot) = agent::total_tokens();
    if agent::total_cost_usd() > 0.0 || it + ot > 0 {
        println!("  cost            : ${:.4}  ({it} in / {ot} out tok)", agent::total_cost_usd());
    }
    if !confirmed.is_empty() {
        println!("{}", color("\n  top confirmed:", "bold"));
        for t in confirmed.iter().take(5) {
            let f = &t.accumulated.representative;
            println!("    • {:8} {}  ({})", t.accumulated.max_severity, f.title.chars().take(60).collect::<String>(), f.loc());
        }
    }
    println!();
}

// ──────────────────────────────────────────────────────────────────────────────
// commands
// ──────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn cmd_fire(
    target_name: String,
    model: String,
    runs: usize,
    concurrency: usize,
    focus: Option<String>,
    variants_arg: Option<String>,
    models_arg: Option<String>,
    do_threat_model: bool,
    do_recon: bool,
    do_chain: bool,
    do_dedup: bool,
    do_repo_map: bool,
    detector_override: Option<String>,
    verify_top: usize,
    votes: usize,
    diff: Option<String>,
    resume: Option<String>,
) -> Result<()> {
    let mut target = TargetConfig::load(&target_name, &targets_root())?;
    if let Some(d) = &detector_override {
        target.detector = d.clone();
    }
    let (context_block, ctx_files) = load_full_context(&target.context_dir(), &target.source_root);
    if !ctx_files.is_empty() {
        println!("{}", color(&format!("  context: fed {} doc(s) from context/", ctx_files.len()), "dim"));
    }

    let models = {
        let m = csv(&models_arg);
        if m.is_empty() { vec![model.clone()] } else { m }
    };
    let variants = {
        let v = csv(&variants_arg);
        if v.is_empty() { vec!["default".to_string()] } else { v }
    };

    let is_resume = resume.is_some();
    let mut threat_model: Option<ThreatModel> = None;
    let (results_dir, specs): (PathBuf, Vec<Spec>) = if let Some(rd) = resume {
        let rd = PathBuf::from(rd);
        let raw = std::fs::read_to_string(rd.join("salvo.json")).context("reading salvo.json for --resume")?;
        let manifest = permute::SalvoManifest::parse(&raw).context("parsing salvo.json for --resume")?;
        manifest.check_resumable(&target.name)?;
        (rd, manifest.specs)
    } else {
        let results_dir = new_results_dir(&target.name)?;
        let mut focus_areas: Vec<String> = if do_threat_model {
            println!("{}", color("  ◆ threat-modeling…", "threat"));
            let (tm, _shas, _a) = stages::threat_model::run_threat_model(
                &target, &model, &context_block,
                Some(results_dir.join("threat_model_transcript.jsonl")), Some("  [threat]".into()),
            ).await?;
            println!("{}", color(&format!("    → {} components, {} focus areas", tm.components.len(), tm.focus_areas.len()), "threat"));
            stages::report::write_threat_model(&results_dir, &tm)?;
            stages::report::write_threat_model(&target.target_dir, &tm)?;
            let fa = tm.focus_areas.clone();
            threat_model = Some(tm);
            fa
        } else if do_recon {
            println!("{}", color("  ◆ recon…", "recon"));
            let (areas, _a) = stages::recon::run_recon(&target, &model, &context_block, Some(results_dir.join("recon_transcript.jsonl")), Some("  [recon]".into())).await?;
            areas
        } else if let Some(f) = &focus {
            f.split(';').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
        } else {
            target.focus_areas.clone()
        };

        if let Some(base) = &diff {
            let files = context::git_changed_files(&target.source_root, base);
            if files.is_empty() {
                println!("{}", color(&format!("  [diff] no changed files vs {base}; using full focus set"), "dim"));
            } else {
                println!("{}", color(&format!("  [diff] scoping to {} changed file(s) vs {base}", files.len()), "dim"));
                focus_areas = vec![format!(
                    "ONLY review the files changed since {base}: {}. Restrict your analysis to these files and the code they directly touch.",
                    files.join(", ")
                )];
            }
        }

        let specs = build_matrix(&focus_areas, &variants, &models, runs);
        let manifest = permute::SalvoManifest::new(&target.name, specs.clone());
        lock::write_atomic(&results_dir.join("salvo.json"), serde_json::to_string_pretty(&manifest)?.as_bytes())?;
        (results_dir, specs)
    };

    // Banner
    let focuses: Vec<String> = {
        let mut s: Vec<String> = specs.iter().map(|x| x.focus_area.clone().unwrap_or_else(|| "none".into())).collect();
        s.dedup();
        s
    };
    println!("{}", color("\n  ╔══════════════════════════════════════════╗", "cannon"));
    println!("{}", color("  ║   V U L N - S C A N   C A N N O N         ║", "cannon"));
    println!("{}", color("  ╚══════════════════════════════════════════╝", "cannon"));
    println!("  target   : {}  ({})", color(&target.name, "bold"), target.detector);
    println!("  source   : {}", target.source_root.display());
    println!("  salvo    : {} rounds  = {} focus × {} variant × {} model × runs", color(&specs.len().to_string(), "bold"), focuses.len(), variants.len(), models.len());
    println!();

    // Reachability oracle: build the repo trust-graph before the salvo so the
    // verifier can consult it (it loads repo_map.json from the target dir).
    if do_repo_map && !is_resume {
        println!("{}", color("  ◆ mapping repository trust-graph…", "threat"));
        match stages::repomap::run_repomap(&target, &model, &context_block, Some(results_dir.join("repo_map_transcript.jsonl")), Some("  [map]".into())).await {
            Ok((graph, _)) => {
                let _ = save_repo_graph(&target, &graph);
                println!("{}", color(&format!("    → {} nodes, {} edges, {} untrusted entry point(s) (verifier oracle)", graph.nodes.len(), graph.edges.len(), graph.untrusted_entries().len()), "threat"));
            }
            Err(e) => println!("{}", color(&format!("    repo-map failed: {e}"), "dim")),
        }
    }

    let rounds = runner::run_salvo(&target, &specs, &results_dir, &context_block, concurrency, is_resume).await;

    let accumulated = accumulate(&rounds);
    let raw: usize = rounds.iter().map(|r| r.findings.len()).sum();
    println!("{}", color(&format!("\n  ⊕ accumulated {} raw → {} unique findings", raw, accumulated.len()), "bold"));

    let accumulated = if do_dedup {
        let before = accumulated.len();
        let merged = stages::dedup::run_dedup(&target, accumulated, &model, Some(results_dir.join("dedup_transcript.jsonl")), Some("  [dedup]".into())).await;
        println!("{}", color(&format!("  ⊕ semantic dedup → {} unique ({} merged)", merged.len(), before.saturating_sub(merged.len())), "dim"));
        merged
    } else {
        accumulated
    };

    let verdicts = verify_all(&target, &accumulated, &model, &results_dir, concurrency, verify_top, votes).await;
    let triaged = triage(&accumulated, &verdicts);

    // Merge into the persistent ledger (sticky human decisions). Reload-under-lock
    // so a concurrent run's findings aren't clobbered by this merge.
    let (led, (added, updated)) = Ledger::update(&target.target_dir, &target.name, |led| {
        led.merge(&triaged, &results_dir.display().to_string())
    })?;
    println!("{}", color(&format!("  ⊙ ledger: +{added} new, {updated} updated → {}", Ledger::md_path(&target.target_dir).display()), "report"));

    // Chains over the confirmed ledger set.
    let chains: Vec<Chain> = if do_chain {
        let confirmed = led.chainable("confirmed");
        if confirmed.is_empty() {
            println!("{}", color("  ⛓ no confirmed findings to chain", "dim"));
            Vec::new()
        } else {
            println!("{}", color(&format!("\n  ⛓ chaining {} confirmed finding(s)…", confirmed.len()), "chain"));
            let cands = ledger_to_candidates(&confirmed);
            let (chains, _shas, _a) = stages::chain::run_chain(&target, &cands, &model, &context_block, Some(results_dir.join("chain_transcript.jsonl")), Some("  [chain]".into())).await?;
            println!("{}", color(&format!("    → {} chain(s)", chains.len()), "chain"));
            chains
        }
    } else {
        Vec::new()
    };

    stages::report::write_report(&results_dir, &target.name, &rounds, &accumulated, &triaged, &chains, threat_model.as_ref(), specs.len())?;
    if !chains.is_empty() {
        stages::report::write_chains(&target.target_dir, &chains)?;
    }

    final_summary(&results_dir, &triaged, &chains);
    Ok(())
}


// ──────────────────────────────────────────────────────────────────────────────
// PERMUTE — signal-driven, human-gated, cost-estimated permutation
// ──────────────────────────────────────────────────────────────────────────────

fn now_stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()
}

fn read_line(prompt: &str) -> String {
    use std::io::Write;
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

/// Run the selected generators and drop their proposals into the queue (deduped,
/// cost-estimated). Returns how many new proposals were added.
async fn run_generators(q: &mut queue::Queue, target: &TargetConfig, model: &str, sources: &[String], max: usize, research: bool) -> usize {
    let now = now_stamp();
    let mut added = 0usize;
    for s in sources {
        let props: Vec<queue::Proposal> = match s.as_str() {
            "commits" | "commit-archaeology" => generators::commits::propose(target, max),
            "threat-model" | "threatmodel" => generators::threatmodel::propose(target, max),
            "threat-intel" | "intel" => generators::intel::propose(target, max),
            "evolution" | "evolve" => {
                println!("{}", color("    evolution: breeding variants (LLM mutation)…", "dim"));
                generators::evolve::propose(target, model, 3, max).await
            }
            other => {
                println!("{}", color(&format!("    (unknown source '{other}' — valid: {})", queue::SOURCES.join(", ")), "dim"));
                Vec::new()
            }
        };
        let mut n = 0;
        for p in props {
            if q.add(p, &now).is_some() {
                n += 1;
            }
        }
        println!("{}", color(&format!("    {s:18} +{n} proposal(s)"), if n > 0 { "report" } else { "dim" }));
        added += n;
    }
    if research {
        println!("{}", color("    threat-intel-research: researching live CVEs (web)…", "dim"));
        let props = generators::intel::research(target, model, max).await;
        let mut n = 0;
        for p in props {
            if q.add(p, &now).is_some() {
                n += 1;
            }
        }
        println!("{}", color(&format!("    {:18} +{n} proposal(s)", "intel-research"), if n > 0 { "report" } else { "dim" }));
        added += n;
    }
    added
}

fn budget_line(q: &queue::Queue) -> String {
    let cap = q.budget_cap.map(|c| format!("${c:.2} cap")).unwrap_or_else(|| "no cap".into());
    format!("budget › ${:.2} committed of {} · ${:.2} spent · ~${:.3}/round", q.committed(), cap, q.spent, q.cost_per_round)
}

fn show_card(p: &queue::Proposal) {
    println!();
    println!(
        "{}",
        color(&format!("  ▸ {}  {}  ·  yield {:.2}  ·  ~${:.2} ({} round{})", p.id, p.source, p.yield_score, p.est_cost, p.est_rounds, if p.est_rounds == 1 { "" } else { "s" }), "cannon")
    );
    println!("    {}", color(&p.title, "bold"));
    if !p.rationale.is_empty() {
        println!("    └ {}", p.rationale.chars().take(150).collect::<String>());
    }
    if let Some(focus) = p.spec.focus_areas.first() {
        println!("    {} {}", color("focus ›", "dim"), color(&focus.chars().take(170).collect::<String>(), "dim"));
    }
}

/// Walk the pending proposals, best-yield first, and let the human decide.
/// Returns true if the user wants to fire the approved set now.
async fn interactive_review(q: &mut queue::Queue, target: &TargetConfig, model: &str, sources: &[String], max: usize) -> Result<bool> {
    let mut suggestions: Vec<String> = Vec::new();
    loop {
        let next = q.pending().first().map(|p| (*p).clone());
        let p = match next {
            Some(p) => p,
            None => {
                println!("{}", color("\n  ✓ queue reviewed — no more pending proposals.", "report"));
                return Ok(true);
            }
        };
        show_card(&p);
        println!("    {}", color(&budget_line(q), "dim"));
        let ans = read_line(&color("  [k]ick · [s]kip · [d]efer · [a]pprove-all · [r]e-permute · [g]o fire · [q]uit · or type a suggestion › ", "verify"));
        let cmd = ans.chars().next().map(|c| c.to_ascii_lowercase());
        match (ans.as_str(), cmd) {
            ("k", _) | ("kick", _) => match q.approve(&p.id) {
                Ok(()) => println!("    {}", color(&format!("✓ approved {} — scheduled", p.id), "report")),
                Err(e) => {
                    println!("    {}", color(&format!("✗ {e}"), "red"));
                    let _ = q.set_status(&p.id, "deferred");
                }
            },
            ("s", _) | ("skip", _) => {
                let _ = q.set_status(&p.id, "skipped");
            }
            ("d", _) | ("defer", _) => {
                let _ = q.set_status(&p.id, "deferred");
            }
            ("a", _) | ("all", _) => {
                let ids: Vec<String> = q.pending().iter().map(|x| x.id.clone()).collect();
                let mut ap = 0;
                for id in ids {
                    if q.approve(&id).is_ok() {
                        ap += 1;
                    } else {
                        let _ = q.set_status(&id, "deferred");
                    }
                }
                println!("    {}", color(&format!("✓ approved {ap} under the cap (rest deferred)"), "report"));
                return Ok(true);
            }
            ("r", _) | ("re-permute", _) | ("repermute", _) => {
                println!("{}", color("  ↻ re-permuting…", "cannon"));
                let n = run_generators(q, target, model, sources, max, false).await;
                println!("    {}", color(&format!("+{n} new proposal(s)"), "report"));
            }
            ("g", _) | ("go", _) => return Ok(true),
            ("q", _) | ("quit", _) => return Ok(false),
            ("", _) | ("?", _) | ("help", _) => {
                println!("    k=approve  s=skip(no)  d=defer(later)  a=approve all  r=regenerate  g=fire approved now  q=quit");
                println!("    …or just type a hunch — \"focus on the GraphQL resolvers\" — to seed a directed permutation.");
            }
            (text, _) => {
                // a free-text suggestion → a top-priority manual proposal + steer future re-permutes
                suggestions.push(text.to_string());
                let mut mp = queue::Proposal::new(
                    "manual",
                    format!("Your hunt: {}", text.chars().take(56).collect::<String>()),
                    "User-directed permutation.",
                    queue::ProposalSpec { focus_areas: vec![format!("USER-DIRECTED HUNT. {text}")], runs: 1, ..Default::default() },
                    1.0,
                );
                mp.seeded_by = Some(text.to_string());
                match q.add(mp, &now_stamp()) {
                    Some(id) => println!("    {}", color(&format!("+ {id} seeded from your suggestion (queued next)"), "report")),
                    None => println!("    {}", color("(a similar suggestion is already queued)", "dim")),
                }
            }
        }
        q.save(&target.target_dir)?;
    }
}

/// Expand a proposal's spec into a salvo, fire it, accumulate → (verify) → merge
/// to the ledger. Returns (actual $, findings, confirmed, results_dir).
async fn execute_proposal(target: &TargetConfig, spec: &queue::ProposalSpec, model: &str, concurrency: usize) -> Result<(f64, usize, usize, String)> {
    let focus_areas = if spec.focus_areas.is_empty() { target.focus_areas.clone() } else { spec.focus_areas.clone() };
    let variants = if spec.variants.is_empty() { vec!["default".to_string()] } else { spec.variants.clone() };
    let models = if spec.models.is_empty() { vec![model.to_string()] } else { spec.models.clone() };
    let specs = build_matrix(&focus_areas, &variants, &models, spec.runs.max(1));
    let (ctx, _) = load_full_context(&target.context_dir(), &target.source_root);
    let rd = new_results_dir(&format!("permute-{}", target.name))?;
    let before = agent::total_cost_usd();
    let rounds = runner::run_salvo(target, &specs, &rd, &ctx, concurrency, false).await;
    let accumulated = accumulate(&rounds);

    let (triaged, confirmed) = if spec.verify {
        let votes = if spec.votes > 0 { spec.votes } else { DEFAULT_VOTES };
        let verdicts = verify_items(target, accumulated.clone(), model, rd.join("verify"), concurrency.max(1), votes).await;
        let triaged = triage(&accumulated, &verdicts);
        let c = triaged.iter().filter(|t| t.confirmed()).count();
        (triaged, c)
    } else {
        (triage(&accumulated, &BTreeMap::new()), 0)
    };
    // Reload-under-lock merge so a concurrent run isn't clobbered.
    Ledger::update(&target.target_dir, &target.name, |led| {
        led.merge(&triaged, &rd.display().to_string());
    })?;
    let cost = (agent::total_cost_usd() - before).max(0.0);
    Ok((cost, accumulated.len(), confirmed, rd.display().to_string()))
}

/// Fire every approved proposal under the budget cap, recording actuals back into
/// the queue (which recalibrates the $/round estimate).
async fn execute_approved(q: &mut queue::Queue, target: &TargetConfig, model: &str, concurrency: usize) -> Result<()> {
    let ids: Vec<String> = q.approved().iter().map(|p| p.id.clone()).collect();
    if ids.is_empty() {
        println!("{}", color("  nothing approved to fire.", "dim"));
        return Ok(());
    }
    println!("{}", color(&format!("\n  ◆ firing {} approved proposal(s)…", ids.len()), "cannon"));
    for id in ids {
        if let Some(cap) = q.budget_cap {
            if q.spent >= cap - 1e-9 {
                println!("{}", color(&format!("  ⛔ budget cap ${cap:.2} reached (${:.2} spent) — remaining proposals stay queued", q.spent), "red"));
                break;
            }
        }
        let p = match q.by_id_mut(&id) {
            Some(p) => p.clone(),
            None => continue,
        };
        let _ = q.set_status(&id, "running");
        q.save(&target.target_dir)?;
        println!("{}", color(&format!("\n  ▶ {} · {} (~${:.2})", id, p.title.chars().take(58).collect::<String>(), p.est_cost), "bold"));
        match execute_proposal(target, &p.spec, model, concurrency).await {
            Ok((cost, findings, confirmed, rdir)) => {
                q.record_result(&id, cost, findings, confirmed, &rdir);
                if p.source == "evolution" {
                    if let Some(v) = p.spec.variants.first() {
                        generators::evolve::record_fitness(&target.target_dir, v, confirmed as f64);
                    }
                }
                let delta = cost - p.est_cost;
                println!(
                    "{}",
                    color(&format!("  ✓ {id}: {findings} finding(s), {confirmed} confirmed · actual ${cost:.2} (est ${:.2}, {}${:.2})", p.est_cost, if delta >= 0.0 { "+" } else { "−" }, delta.abs()), "report")
                );
            }
            Err(e) => {
                let _ = q.set_status(&id, "failed");
                println!("{}", color(&format!("  ✗ {id} failed: {e}"), "red"));
            }
        }
        q.save(&target.target_dir)?;
    }
    println!("{}", color(&format!("\n  Σ spent ${:.2} this session · $/round recalibrated to ~${:.3}", q.spent, q.cost_per_round), "bold"));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_permute(target_name: String, model: String, sources_arg: Option<String>, max: usize, budget: Option<f64>, research: bool, yes: bool, plan_only: bool, concurrency: usize) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let mut q = queue::Queue::load(&target.target_dir);
    if let Some(b) = budget {
        q.budget_cap = Some(b);
    }
    let sources = {
        let v = csv(&sources_arg);
        if v.is_empty() { vec!["commits".into(), "threat-model".into(), "threat-intel".into()] } else { v }
    };

    println!("{}", color("\n  ╔══════════════════════════════════════════╗", "cannon"));
    println!("{}", color("  ║   P E R M U T A T I O N   P L A N N E R   ║", "cannon"));
    println!("{}", color("  ╚══════════════════════════════════════════╝", "cannon"));
    println!("  target  : {}", color(&target.name, "bold"));
    println!("  signals : {}", sources.join(", "));
    println!("  {}", budget_line(&q));
    println!("{}", color(&format!("\n  ◆ generating proposals (≤{max} per signal)…"), "cannon"));

    run_generators(&mut q, &target, &model, &sources, max, research).await;
    q.save(&target.target_dir)?;

    let pending = q.pending().len();
    if pending == 0 {
        println!("{}", color("\n  no pending proposals. (`cannon queue list` to see the whole queue.)", "dim"));
        if q.approved().is_empty() {
            return Ok(());
        }
    } else {
        println!("{}", color(&format!("\n  {pending} proposal(s) await your decision."), "bold"));
    }

    let fire = if yes {
        let ids: Vec<String> = q.pending().iter().map(|p| p.id.clone()).collect();
        let mut ap = 0;
        for id in ids {
            if q.approve(&id).is_ok() {
                ap += 1;
            } else {
                let _ = q.set_status(&id, "deferred");
            }
        }
        println!("{}", color(&format!("  ✓ --yes: auto-approved {ap} under the cap", ), "report"));
        true
    } else {
        interactive_review(&mut q, &target, &model, &sources, max).await?
    };
    q.save(&target.target_dir)?;

    if plan_only || !fire {
        let n = q.approved().len();
        println!("{}", color(&format!("\n  {n} proposal(s) scheduled. Fire them with `cannon queue run {target_name}`.", ), "report"));
        return Ok(());
    }
    execute_approved(&mut q, &target, &model, concurrency).await?;
    q.save(&target.target_dir)?;
    Ok(())
}

async fn cmd_queue(sub: QueueCmd) -> Result<()> {
    match sub {
        QueueCmd::List { target } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let q = queue::Queue::load(&t.target_dir);
            if q.proposals.is_empty() {
                println!("Queue empty. Run `cannon permute {target}` to generate proposals.");
                return Ok(());
            }
            println!("{}", color(&budget_line(&q), "dim"));
            let summary = q.counts().iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("  ");
            println!("{}", color(&format!("  {summary}"), "dim"));
            println!("{:<7} {:<10} {:<18} {:>7} {:>5}  TITLE", "ID", "STATUS", "SOURCE", "EST$", "YIELD");
            let mut v: Vec<&queue::Proposal> = q.proposals.iter().collect();
            v.sort_by(|a, b| b.yield_score.partial_cmp(&a.yield_score).unwrap_or(std::cmp::Ordering::Equal));
            for p in v {
                let extra = p.actual_cost.map(|c| format!("  → {} found, {} confirmed, ${:.2}", p.findings.unwrap_or(0), p.confirmed.unwrap_or(0), c)).unwrap_or_default();
                println!("{:<7} {:<10} {:<18} {:>7.2} {:>5.2}  {}{}", p.id, p.status, p.source, p.est_cost, p.yield_score, p.title.chars().take(50).collect::<String>(), color(&extra, "dim"));
            }
        }
        QueueCmd::Run { target, model, concurrency } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let mut q = queue::Queue::load(&t.target_dir);
            execute_approved(&mut q, &t, &resolve_model(model), concurrency).await?;
            q.save(&t.target_dir)?;
        }
        QueueCmd::Clear { target } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let mut q = queue::Queue::load(&t.target_dir);
            let n = q.prune_decided();
            q.save(&t.target_dir)?;
            println!("  cleared {n} decided proposal(s); {} live remain.", q.proposals.len());
        }
        QueueCmd::Budget { target, cap } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let mut q = queue::Queue::load(&t.target_dir);
            q.budget_cap = if cap <= 0.0 { None } else { Some(cap) };
            q.save(&t.target_dir)?;
            println!("  budget cap {}", q.budget_cap.map(|c| format!("set to ${c:.2}")).unwrap_or_else(|| "cleared".into()));
        }
    }
    Ok(())
}

async fn cmd_chain(target_name: String, model: String, scope: String) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let (context_block, _) = load_full_context(&target.context_dir(), &target.source_root);
    let led = Ledger::load(&target.target_dir, &target.name);
    let selected = led.chainable(&scope);
    if selected.is_empty() {
        println!("No findings in scope '{scope}' to chain. Triage some findings first (cannon findings set / tui).");
        return Ok(());
    }
    println!("{}", color(&format!("  ⛓ chaining {} finding(s) in scope '{}'…", selected.len(), scope), "chain"));
    let cands = ledger_to_candidates(&selected);
    let (chains, _shas, _a) = stages::chain::run_chain(&target, &cands, &model, &context_block, None, Some("  [chain]".into())).await?;
    stages::report::write_chains(&target.target_dir, &chains)?;
    println!("{}", color(&format!("    → {} chain(s) → {}", chains.len(), target.target_dir.join("CHAINS.md").display()), "chain"));
    Ok(())
}

async fn cmd_patch(target_name: String, model: String, scope: String, concurrency: usize, top: usize) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let led = Ledger::load(&target.target_dir, &target.name);
    let mut selected: Vec<&ledger::LedgerFinding> = led.chainable(&scope);
    selected.sort_by_key(|f| std::cmp::Reverse(artifacts::sev_rank(&f.severity)));
    if top > 0 {
        selected.truncate(top);
    }
    if selected.is_empty() {
        println!("No findings in scope '{scope}' to patch. Confirm some first (cannon findings set / tui).");
        return Ok(());
    }
    let out_dir = target.target_dir.join("PATCHES");
    std::fs::create_dir_all(&out_dir)?;
    let cands: Vec<stages::patch::PatchCandidate> = selected
        .iter()
        .map(|f| stages::patch::PatchCandidate {
            id: f.id.clone(),
            title: f.title.clone(),
            file: f.file.clone(),
            line: f.line,
            severity: f.severity.clone(),
            cwe: f.cwe.clone(),
            description: f.description.clone(),
        })
        .collect();
    println!("{}", color(&format!("  🔧 patching {} finding(s) in scope '{}'…", cands.len(), scope), "report"));

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let target_a = Arc::new(target.clone());
    let out_a = Arc::new(out_dir.clone());
    let mut set: JoinSet<stages::patch::PatchResult> = JoinSet::new();
    for cand in cands {
        let sem = sem.clone();
        let target_a = target_a.clone();
        let out_a = out_a.clone();
        let model = model.clone();
        set.spawn(async move {
            let _p = sem.acquire_owned().await.unwrap();
            println!("    🔧 {} {}", cand.id, cand.title.chars().take(50).collect::<String>());
            let r = stages::patch::run_patch_one(&target_a, &cand, &model, &out_a, Some(format!("  [patch {}]", cand.id))).await;
            let mark = match r.review.as_str() { "APPROVED" => "✅", "CONCERNS" => "⚠", _ => "∅" };
            println!("    {mark} {} → {} ({} byte diff)", r.id, r.review, r.diff.len());
            r
        });
    }
    let mut results = Vec::new();
    while let Some(x) = set.join_next().await {
        if let Ok(r) = x {
            results.push(r);
        }
    }
    results.sort_by(|a, b| a.id.cmp(&b.id));

    lock::write_atomic(&out_dir.join("PATCHES.json"), serde_json::to_string_pretty(&results)?.as_bytes())?;
    let mut md = format!("# Patches — {}\n\n_Drafts for human review — cannon never applies diffs._\n\n", target.name);
    for r in &results {
        md.push_str(&format!("## {} · `{}`\n- review: **{}**\n", r.id, r.file, r.review));
        if !r.review_notes.is_empty() {
            md.push_str(&format!("- reviewer: {}\n", r.review_notes));
        }
        md.push('\n');
        if r.diff.is_empty() {
            md.push_str(&format!("_no patch: {}_\n\n", r.rationale));
        } else {
            md.push_str(&format!("```diff\n{}\n```\n\n", r.diff));
        }
    }
    lock::write_atomic(&out_dir.join("PATCHES.md"), md.as_bytes())?;
    let (it, ot) = agent::total_tokens();
    println!("{}", color(&format!("  → {}  (${:.4}, {} tok)", out_dir.join("PATCHES.md").display(), agent::total_cost_usd(), it + ot), "report"));
    Ok(())
}

async fn cmd_threat_model(target_name: String, model: String) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let (context_block, _) = load_full_context(&target.context_dir(), &target.source_root);
    let (tm, _shas, _a) = stages::threat_model::run_threat_model(&target, &model, &context_block, None, Some("  [threat]".into())).await?;
    stages::report::write_threat_model(&target.target_dir, &tm)?;
    println!("{}", color(&format!("\n  → {}", target.target_dir.join("THREAT_MODEL.md").display()), "bold"));
    println!("  components: {}  flows: {}  focus areas: {}", tm.components.len(), tm.flows.len(), tm.focus_areas.len());
    Ok(())
}

fn save_repo_graph(target: &TargetConfig, graph: &repomap::RepoGraph) -> Result<()> {
    std::fs::create_dir_all(target.target_dir.join(".cannon"))?;
    lock::write_atomic(&repomap::RepoGraph::json_path(&target.target_dir), serde_json::to_string_pretty(graph)?.as_bytes())?;
    Ok(())
}

async fn cmd_map(target_name: String, model: String) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let (context_block, _) = load_full_context(&target.context_dir(), &target.source_root);
    println!("{}", color("  ◆ mapping repository trust-graph…", "threat"));
    let (graph, _a) = stages::repomap::run_repomap(&target, &model, &context_block, None, Some("  [map]".into())).await?;
    save_repo_graph(&target, &graph)?;
    if graph.is_empty() {
        println!("{}", color("  (the agent produced no graph nodes — try a clearer target description or `--model opus`)", "dim"));
        return Ok(());
    }
    let entries = graph.untrusted_entries();
    println!(
        "{}",
        color(&format!("  → {} nodes, {} edges, {} untrusted entry point(s) → {}", graph.nodes.len(), graph.edges.len(), entries.len(), repomap::RepoGraph::json_path(&target.target_dir).display()), "report")
    );
    for n in entries.iter().take(8) {
        println!("    ⇢ {}  ({})", n.id, if n.file.is_empty() { "—".into() } else { n.loc() });
    }
    Ok(())
}

fn cmd_report(results_dir: String) -> Result<()> {
    let name = target_from_results(&results_dir).context("deriving target from results dir")?;
    let rd = PathBuf::from(&results_dir);
    let rounds = runner::load_rounds(&rd);
    let accumulated = accumulate(&rounds);
    // reuse existing verdicts if present
    let verdicts: BTreeMap<String, Verdict> = std::fs::read_to_string(rd.join("triage.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<TriagedFinding>>(&s).ok())
        .map(|ts| ts.into_iter().map(|t| (t.accumulated.signature.clone(), t.verdict)).collect())
        .unwrap_or_default();
    let triaged = triage(&accumulated, &verdicts);
    let chains: Vec<Chain> = std::fs::read_to_string(rd.join("chains.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    stages::report::write_report(&rd, &name, &rounds, &accumulated, &triaged, &chains, None, rounds.len())?;
    println!("  → {}", rd.join("REPORT.md").display());
    Ok(())
}

async fn cmd_seed(
    target_name: String,
    files: Vec<String>,
    format: String,
    do_verify: bool,
    model: String,
    concurrency: usize,
) -> Result<()> {
    if files.is_empty() {
        anyhow::bail!("no files given. Usage: cannon seed <target> <file...> [--format auto|sarif|semgrep|json|csv] [--verify]");
    }
    let target = TargetConfig::load(&target_name, &targets_root())?;
    // Parse the seed files (no ledger involved) before taking the lock.
    let mut parsed: Vec<(String, seed::Seeded)> = Vec::new();
    for file in &files {
        parsed.push((file.clone(), seed::parse_file(Path::new(file), &format)?));
    }
    let (led, (total_added, total_updated, new_sigs)) = Ledger::update(&target.target_dir, &target.name, |led| {
        let (mut total_added, mut total_updated): (usize, usize) = (0, 0);
        let mut new_sigs: Vec<String> = Vec::new();
        for (file, seeded) in &parsed {
            let (a, u, ns) = led.merge_seeds(&seeded.findings, &seeded.source);
            println!(
                "  seeded {} finding(s) from {} ({})  → +{a} new, {u} updated",
                seeded.findings.len(), file, seeded.source
            );
            total_added += a;
            total_updated += u;
            new_sigs.extend(ns);
        }
        (total_added, total_updated, new_sigs)
    })?;
    println!(
        "{}",
        color(&format!("  ⊙ ledger: +{total_added} new, {total_updated} updated → {}", Ledger::md_path(&target.target_dir).display()), "report")
    );

    if do_verify && !new_sigs.is_empty() {
        let items: Vec<AccumulatedFinding> = led
            .findings
            .iter()
            .filter(|f| new_sigs.contains(&f.signature))
            .map(|f| f.as_accumulated())
            .collect();
        println!("{}", color(&format!("\n  ⚖ verifying {} newly-seeded finding(s)…", items.len()), "verify"));
        let verdicts = verify_items(&target, items, &model, target.target_dir.join(".cannon").join("verify"), concurrency, DEFAULT_VOTES).await;
        let (_, (c, fp)) = Ledger::update(&target.target_dir, &target.name, |led| led.apply_verdicts(&verdicts))?;
        println!("{}", color(&format!("  → {c} confirmed, {fp} false-positive after verification"), "report"));
    } else if do_verify {
        println!("  (nothing new to verify)");
    } else {
        println!("  run `cannon verify {target_name}` to adversarially triage the seeded backlog.");
    }
    Ok(())
}

async fn cmd_verify(target_name: String, model: String, concurrency: usize, all: bool, votes: usize) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let led = Ledger::load(&target.target_dir, &target.name);
    let items: Vec<AccumulatedFinding> = led
        .findings
        .iter()
        .filter(|f| all || f.verifier_verdict.is_none() || f.status == "new")
        .map(|f| f.as_accumulated())
        .collect();
    if items.is_empty() {
        println!("Nothing to verify — every finding already has a verdict. Use --all to re-verify.");
        return Ok(());
    }
    println!("{}", color(&format!("  ⚖ verifying {} finding(s) × {} votes…", items.len(), votes), "verify"));
    let verdicts = verify_items(&target, items, &model, target.target_dir.join(".cannon").join("verify"), concurrency, votes).await;
    let (_, (c, fp)) = Ledger::update(&target.target_dir, &target.name, |led| led.apply_verdicts(&verdicts))?;
    println!("{}", color(&format!("  → {c} confirmed, {fp} false-positive (ledger updated → {})", Ledger::md_path(&target.target_dir).display()), "report"));
    Ok(())
}

/// Labeled corpus targets (each dir needs config.yaml + labels.json), sorted.
fn corpus_targets(root: &Path, corpus: &str) -> Result<Vec<PathBuf>> {
    let mut targets: Vec<PathBuf> = std::fs::read_dir(root)
        .with_context(|| format!("reading corpus {corpus}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.join("config.yaml").is_file() && p.join("labels.json").is_file())
        .collect();
    targets.sort();
    if targets.is_empty() {
        anyhow::bail!("no labeled targets (each needs config.yaml + labels.json) under {corpus}");
    }
    Ok(targets)
}

/// Scan a set of labeled targets with a given prompt `variant` and score each
/// against its labels — the reusable core shared by `measure` and `tune`.
#[allow(clippy::too_many_arguments)]
async fn score_targets(
    targets: &[PathBuf],
    model: &str,
    variant: &str,
    do_verify: bool,
    votes: usize,
    tol: u32,
    concurrency: usize,
    quiet: bool,
) -> (bench::BenchScore, Vec<(String, bench::BenchScore)>) {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set: JoinSet<Option<(String, bench::BenchScore)>> = JoinSet::new();
    // `tdir` is captured by the `async move` task below, so it must be owned
    // (the clone is required for the spawned future's 'static bound).
    #[allow(clippy::unnecessary_to_owned)]
    for tdir in targets.iter().cloned() {
        let sem = sem.clone();
        let model = model.to_string();
        let variant = variant.to_string();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let target = TargetConfig::load(&tdir.display().to_string(), "").ok()?;
            let labels: Vec<bench::Label> = serde_json::from_str(&std::fs::read_to_string(tdir.join("labels.json")).ok()?).ok()?;
            let (ctx, _) = load_full_context(&target.context_dir(), &target.source_root);
            let specs = build_matrix(&target.focus_areas, std::slice::from_ref(&variant), std::slice::from_ref(&model), 1);
            let results_dir = new_results_dir(&format!("bench-{}", target.name)).ok()?;
            let rounds = runner::run_salvo(&target, &specs, &results_dir, &ctx, 1, false).await;
            let accumulated = accumulate(&rounds);
            let detected: Vec<bench::Detected> = if do_verify {
                let verdicts = verify_items(&target, accumulated.clone(), &model, results_dir.join("verify"), 2, votes).await;
                triage(&accumulated, &verdicts)
                    .iter()
                    .filter(|t| t.confirmed())
                    .map(|t| bench::Detected { file: t.accumulated.representative.file.clone(), line: t.accumulated.representative.line, cwe: t.accumulated.representative.cwe.clone() })
                    .collect()
            } else {
                accumulated.iter().map(|a| bench::Detected { file: a.representative.file.clone(), line: a.representative.line, cwe: a.representative.cwe.clone() }).collect()
            };
            let s = bench::score(&detected, &labels, tol);
            if !quiet {
                println!("  {:22} TP {} FP {} FN {}   P={:.2} R={:.2} F1={:.2}", target.name, s.tp, s.fp, s.fn_, s.precision(), s.recall(), s.f1());
            }
            Some((target.name.clone(), s))
        });
    }
    let mut overall = bench::BenchScore::default();
    let mut rows: Vec<(String, bench::BenchScore)> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some((name, s))) = res {
            overall.add(&s);
            rows.push((name, s));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    (overall, rows)
}

#[allow(clippy::too_many_arguments)]
async fn cmd_bench(corpus: String, model: String, concurrency: usize, do_verify: bool, votes: usize, tol: u32, against: Option<String>, gate: bool, write_baseline: bool) -> Result<()> {
    let root = PathBuf::from(&corpus);
    let targets = corpus_targets(&root, &corpus)?;

    // Score an EXTERNAL tool's SARIF against the corpus labels, with cannon's
    // exact scorer — apples-to-apples vs Semgrep / CodeQL.
    if let Some(sarif_path) = against {
        let mut all_labels: Vec<bench::Label> = Vec::new();
        for tdir in &targets {
            all_labels.extend(serde_json::from_str::<Vec<bench::Label>>(&std::fs::read_to_string(tdir.join("labels.json"))?)?);
        }
        let seeded = seed::parse_file(Path::new(&sarif_path), "sarif")?;
        let detected: Vec<bench::Detected> = seeded
            .findings
            .iter()
            .map(|f| bench::Detected { file: f.file.clone(), line: f.line, cwe: f.cwe.clone() })
            .collect();
        let s = bench::score(&detected, &all_labels, tol);
        println!("{}", color(&format!("  ── external SARIF: {} ──", sarif_path), "cannon"));
        println!("  {} detections vs {} labels", detected.len(), all_labels.len());
        println!("{}", color(&format!("  TOTAL  TP {} FP {} FN {}", s.tp, s.fp, s.fn_), "bold"));
        println!("{}", color(&format!("  precision {:.3} · recall {:.3} · F1 {:.3}", s.precision(), s.recall(), s.f1()), "bold"));
        return Ok(());
    }

    println!("{}", color(&format!("  ── benchmark: {} target(s){} ──", targets.len(), if do_verify { " (full pipeline)" } else { " (detector only)" }), "cannon"));

    // Targets run concurrently (each OWASP case is its own 1-round target).
    let (overall, rows) = score_targets(&targets, &model, "default", do_verify, votes, tol, concurrency, false).await;

    println!("{}", color(&format!("\n  TOTAL  TP {} FP {} FN {}", overall.tp, overall.fp, overall.fn_), "bold"));
    println!("{}", color(&format!("  precision {:.3} · recall {:.3} · F1 {:.3}", overall.precision(), overall.recall(), overall.f1()), "bold"));
    let report = serde_json::json!({
        "targets": rows.iter().map(|(n, s)| serde_json::json!({"target": n, "tp": s.tp, "fp": s.fp, "fn": s.fn_})).collect::<Vec<_>>(),
        "overall": {"tp": overall.tp, "fp": overall.fp, "fn": overall.fn_, "precision": overall.precision(), "recall": overall.recall(), "f1": overall.f1()},
    });
    lock::write_atomic(&root.join("bench.json"), serde_json::to_string_pretty(&report)?.as_bytes())?;
    println!("  → {}", root.join("bench.json").display());

    // Regression gate: pin a baseline, or fail (exit 2) if F1 dropped below it.
    let baseline_path = root.join("bench-baseline.json");
    if write_baseline {
        let b = tune::Baseline::from_score(&overall);
        lock::write_atomic(&baseline_path, serde_json::to_string_pretty(&b)?.as_bytes())?;
        println!("{}", color(&format!("  ⊙ pinned baseline F1 {:.3} → {}", overall.f1(), baseline_path.display()), "report"));
    } else if gate {
        match std::fs::read_to_string(&baseline_path).ok().and_then(|s| serde_json::from_str::<tune::Baseline>(&s).ok()) {
            Some(b) => {
                if tune::gate(overall.f1(), b.f1, 0.02) {
                    println!("{}", color(&format!("  ✓ GATE PASS — F1 {:.3} vs baseline {:.3}", overall.f1(), b.f1), "bold"));
                } else {
                    eprintln!("{}", ui::ecolor(&format!("  ✗ GATE FAIL — F1 {:.3} regressed below baseline {:.3} (margin 0.02)", overall.f1(), b.f1), "red"));
                    std::process::exit(2);
                }
            }
            None => println!("  (no baseline at {} — run once with --write-baseline to pin one)", baseline_path.display()),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_tune(corpus: String, model: String, variants_arg: Option<String>, do_verify: bool, votes: usize, tol: u32, holdout: f64, concurrency: usize) -> Result<()> {
    let root = PathBuf::from(&corpus);
    let targets = corpus_targets(&root, &corpus)?;
    let variants = {
        let v = csv(&variants_arg);
        if v.is_empty() { vec!["default".to_string()] } else { v }
    };
    let (train, test) = tune::split_corpus(&targets, holdout);
    if train.is_empty() {
        anyhow::bail!("train split is empty (holdout {holdout} too high for {} targets)", targets.len());
    }
    println!(
        "{}",
        color(&format!("  ── tune: {} variant(s) over {} train / {} test target(s){} ──", variants.len(), train.len(), test.len(), if do_verify { " (full pipeline)" } else { " (detector only)" }), "cannon")
    );
    if variants.len() < 2 {
        println!("  note: pass --variants a,b,c to actually compare prompts; one variant just measures it.");
    }

    // Fitness = F1 on the TRAIN split, per variant.
    let mut board: Vec<(String, bench::BenchScore)> = Vec::new();
    for v in &variants {
        let (overall, _) = score_targets(&train, &model, v, do_verify, votes, tol, concurrency, true).await;
        println!("  variant {:14} train  P={:.3} R={:.3} F1={:.3}", v, overall.precision(), overall.recall(), overall.f1());
        board.push((v.clone(), overall));
    }
    let best = tune::select_best(&board).unwrap_or_else(|| variants[0].clone());
    println!("{}", color(&format!("  ★ best on train: '{best}'"), "bold"));

    // Validate the winner on the held-out test split (the honesty check).
    let test_score = if test.is_empty() {
        println!("  (no held-out test split — increase --holdout for an honest generalization check)");
        None
    } else {
        let (overall, _) = score_targets(&test, &model, &best, do_verify, votes, tol, concurrency, true).await;
        println!("{}", color(&format!("  ☑ '{best}' on held-out test: P={:.3} R={:.3} F1={:.3}", overall.precision(), overall.recall(), overall.f1()), "bold"));
        Some(overall)
    };

    let report = serde_json::json!({
        "holdout": holdout,
        "train_targets": train.len(),
        "test_targets": test.len(),
        "leaderboard": board.iter().map(|(v, s)| serde_json::json!({"variant": v, "precision": s.precision(), "recall": s.recall(), "f1": s.f1()})).collect::<Vec<_>>(),
        "best": best,
        "best_on_test": test_score.as_ref().map(|s| serde_json::json!({"precision": s.precision(), "recall": s.recall(), "f1": s.f1()})),
    });
    lock::write_atomic(&root.join("tune.json"), serde_json::to_string_pretty(&report)?.as_bytes())?;
    println!("  → {}", root.join("tune.json").display());
    Ok(())
}

async fn cmd_prove(target: String, model: String, concurrency: usize, votes: usize) -> Result<()> {
    if std::env::var("CANNON_ALLOW_EXEC").ok().as_deref() != Some("1") {
        eprintln!("{}", ui::ecolor("note: PROVE executes the target. Set CANNON_ALLOW_EXEC=1 and run inside a sandbox/VM.", "red"));
    }
    // Force the dynamic (proof-carrying) detector for this run.
    cmd_fire(target, model, 1, concurrency, None, None, None, false, false, false, false, false, Some("dynamic".to_string()), 0, votes, None, None).await
}

async fn cmd_metamorphic(target_name: String, model: String, id: Option<String>, scope: String, concurrency: usize, apply: bool) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let led = Ledger::load(&target.target_dir, &target.name);
    let selected: Vec<(String, AccumulatedFinding)> = led
        .findings
        .iter()
        .filter(|f| {
            if let Some(want) = &id {
                return f.id.eq_ignore_ascii_case(want);
            }
            match scope.as_str() {
                "confirmed" => f.status == "confirmed",
                "uncertain" => f.verifier_verdict.as_deref() == Some("UNCERTAIN"),
                "all" => !["false_positive", "duplicate"].contains(&f.status.as_str()),
                _ => f.status == "confirmed" || f.verifier_verdict.as_deref() == Some("UNCERTAIN"),
            }
        })
        .map(|f| (f.id.clone(), f.as_accumulated()))
        .collect();
    if selected.is_empty() {
        println!("No findings in scope '{scope}' to check. Confirm or verify some first (cannon fire / triage).");
        return Ok(());
    }
    let exec = std::env::var("CANNON_ALLOW_EXEC").ok().as_deref() == Some("1");
    println!(
        "{}",
        color(&format!("  ⟂ metamorphic check on {} finding(s) (scope {scope}{})", selected.len(), if exec { ", execution ENABLED" } else { ", static" }), "verify")
    );
    let dir = target.target_dir.join(".cannon").join("metamorphic");
    std::fs::create_dir_all(&dir)?;

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let target_a = Arc::new(target.clone());
    let mut set: JoinSet<metamorphic::MetamorphicReport> = JoinSet::new();
    for (fid, acc) in selected {
        let sem = sem.clone();
        let target_a = target_a.clone();
        let model = model.clone();
        let dir = dir.clone();
        set.spawn(async move {
            let _p = sem.acquire_owned().await.unwrap();
            println!("    ⟂ {fid} {}", acc.representative.title.chars().take(50).collect::<String>());
            let tp = Some(dir.join(format!("{fid}.jsonl")));
            match stages::metamorphic::run_metamorphic(&target_a, &fid, &acc, &model, tp, Some(format!("  [meta {fid}]"))).await {
                Ok((r, _)) => r,
                Err(e) => metamorphic::MetamorphicReport {
                    id: fid.clone(),
                    signature: acc.signature.clone(),
                    verdict: "INCONCLUSIVE".into(),
                    orig_vulnerable: false,
                    mutant_vulnerable: false,
                    mutation: String::new(),
                    reasoning: format!("error: {e}"),
                    executed: false,
                },
            }
        });
    }
    let mut reports = Vec::new();
    while let Some(x) = set.join_next().await {
        if let Ok(r) = x {
            let mark = match r.verdict.as_str() { "REAL" => "✅", "FALSE_POSITIVE" => "❌", _ => "❔" };
            println!("    {mark} {} {}{}  orig={} mutant={}", r.id, r.verdict, if r.executed { " (executed)" } else { "" }, r.orig_vulnerable, r.mutant_vulnerable);
            reports.push(r);
        }
    }
    reports.sort_by(|a, b| a.id.cmp(&b.id));
    crate::lock::write_atomic(&target.target_dir.join(".cannon").join("metamorphic.json"), serde_json::to_string_pretty(&reports)?.as_bytes())?;

    let mut flipped = 0;
    if apply {
        // Reload-under-lock so verdicts apply to the freshest ledger.
        let (_, n) = Ledger::update(&target.target_dir, &target.name, |led| {
            let mut flipped = 0;
            for r in &reports {
                if let Some(lf) = led.by_id_mut(&r.id) {
                    if lf.triaged_by != "human" {
                        if let Some(ns) = metamorphic::reconcile(r.verdict_enum()) {
                            if lf.status != ns {
                                lf.status = ns.to_string();
                                lf.triaged_by = "auto".into();
                                lf.note = format!("metamorphic {}: orig={}, mutant={}{}", r.verdict, r.orig_vulnerable, r.mutant_vulnerable, if r.executed { " (executed)" } else { "" });
                                flipped += 1;
                            }
                        }
                    }
                }
            }
            flipped
        })?;
        flipped = n;
    }

    let fp = reports.iter().filter(|r| r.verdict == "FALSE_POSITIVE").count();
    let real = reports.iter().filter(|r| r.verdict == "REAL").count();
    println!("{}", color(&format!("  → {real} corroborated REAL · {fp} disproved · {} inconclusive", reports.len() - fp - real), "bold"));
    if apply {
        println!("{}", color(&format!("  ⊙ applied {flipped} status change(s) → {}", Ledger::md_path(&target.target_dir).display()), "report"));
    } else if fp > 0 || real > 0 {
        println!("  (re-run with --apply to write these verdicts back to the ledger)");
    }
    println!("  → {}", target.target_dir.join(".cannon").join("metamorphic.json").display());
    Ok(())
}

async fn cmd_fleet(fleet_path: String, model: String, concurrency: usize, votes: usize) -> Result<()> {
    let fc: fleet::FleetConfig = serde_yaml_ng::from_str(
        &std::fs::read_to_string(&fleet_path).with_context(|| format!("reading {fleet_path}"))?,
    )?;
    if fc.targets.is_empty() {
        anyhow::bail!("fleet file lists no targets");
    }
    println!("{}", color(&format!("  ⛁ fleet: {} service(s)", fc.targets.len()), "cannon"));

    for t in &fc.targets {
        let target = TargetConfig::load(t, &targets_root())?;
        println!("{}", color(&format!("  ◆ scanning {}", target.name), "cannon"));
        let (ctx, _) = load_full_context(&target.context_dir(), &target.source_root);
        let specs = build_matrix(&target.focus_areas, &["default".to_string()], std::slice::from_ref(&model), 1);
        let rd = new_results_dir(&format!("fleet-{}", target.name))?;
        let rounds = runner::run_salvo(&target, &specs, &rd, &ctx, concurrency, false).await;
        let acc = accumulate(&rounds);
        let verdicts = verify_items(&target, acc.clone(), &model, rd.join("verify"), concurrency, votes).await;
        let triaged = triage(&acc, &verdicts);
        Ledger::update(&target.target_dir, &target.name, |led| {
            led.merge(&triaged, &rd.display().to_string());
        })?;
        println!("    {} confirmed", triaged.iter().filter(|t| t.confirmed()).count());
    }

    // Union of confirmed findings across the fleet, tagged by service.
    let owned: Vec<(String, Ledger)> = fc
        .targets
        .iter()
        .filter_map(|t| TargetConfig::load(t, &targets_root()).ok().map(|tc| (tc.name.clone(), Ledger::load(&tc.target_dir, &tc.name))))
        .collect();
    let refs: Vec<(&str, &Ledger)> = owned.iter().map(|(n, l)| (n.as_str(), l)).collect();
    let tagged = fleet::aggregate(&refs);
    println!("{}", color(&format!("\n  ⊕ {} confirmed finding(s) across {} service(s)", tagged.len(), fc.targets.len()), "bold"));
    if tagged.len() < 2 {
        println!("  not enough cross-service findings to chain.");
        return Ok(());
    }

    let cands: Vec<stages::chain::ChainCandidate> = tagged
        .iter()
        .map(|t| stages::chain::ChainCandidate {
            signature: t.signature.clone(),
            title: format!("[{}] {}", t.target, t.title),
            loc: t.loc.clone(),
            severity: t.severity.clone(),
            premise: t.premise.clone(),
            description: t.description.clone(),
        })
        .collect();
    let host = TargetConfig::load(&fc.targets[0], &targets_root())?;
    println!("{}", color("  ⛓ composing cross-service chains…", "chain"));
    let (chains, _, _) = stages::chain::run_chain(&host, &cands, &model, "", None, Some("  [fleet-chain]".into())).await?;

    let out = PathBuf::from(results_root()).join("fleet");
    std::fs::create_dir_all(&out)?;
    stages::report::write_chains(&out, &chains)?;
    let (it, ot) = agent::total_tokens();
    println!(
        "{}",
        color(&format!("  → {} cross-service chain(s) → {}  (${:.4}, {} tok)", chains.len(), out.join("CHAINS.md").display(), agent::total_cost_usd(), it + ot), "report")
    );
    Ok(())
}

fn cmd_ingest(target_name: String, results_dir: String) -> Result<()> {
    let target = TargetConfig::load(&target_name, &targets_root())?;
    let triaged: Vec<TriagedFinding> = serde_json::from_str(
        &std::fs::read_to_string(PathBuf::from(&results_dir).join("triage.json")).context("reading triage.json (run `cannon triage` first)")?,
    )?;
    let (_, (added, updated)) = Ledger::update(&target.target_dir, &target.name, |led| {
        led.merge(&triaged, &results_dir)
    })?;
    println!("  ⊙ ledger: +{added} new, {updated} updated → {}", Ledger::md_path(&target.target_dir).display());
    Ok(())
}

fn cmd_findings(sub: FindingsCmd) -> Result<()> {
    match sub {
        FindingsCmd::List { target } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let led = Ledger::load(&t.target_dir, &t.name);
            if led.findings.is_empty() {
                println!("No findings yet. Run `cannon fire {target}` first.");
                return Ok(());
            }
            println!("{:<7} {:<9} {:<15} {:<8} FINDING", "ID", "SEV", "STATUS", "BY");
            let mut v: Vec<&ledger::LedgerFinding> = led.findings.iter().collect();
            v.sort_by(|a, b| artifacts::sev_rank(&b.severity).cmp(&artifacts::sev_rank(&a.severity)).then(a.id.cmp(&b.id)));
            for f in v {
                println!("{:<7} {:<9} {:<15} {:<8} {}  ({})", f.id, f.severity, f.status, f.triaged_by, f.title.chars().take(54).collect::<String>(), f.loc());
            }
        }
        FindingsCmd::Show { target, id } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let led = Ledger::load(&t.target_dir, &t.name);
            let f = led.findings.iter().find(|x| x.id.eq_ignore_ascii_case(&id)).context("no such finding")?;
            println!("{}", serde_json::to_string_pretty(f)?);
        }
        FindingsCmd::Set { target, id, status, note } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let (_, res) = Ledger::update(&t.target_dir, &t.name, |led| led.set_status(&id, &status, note))?;
            res?;
            println!("  {} → {}", id, status);
        }
        FindingsCmd::Sync { target } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            let (_, changed) = Ledger::update(&t.target_dir, &t.name, |led| led.sync_from_md(&t.target_dir))?;
            println!("  synced {changed} hand-edit(s) from VULN_FINDINGS.md");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{}", ui::ecolor(&format!("error: {e:#}"), "red"));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        // AIM
        Cmd::Aim { target, model } => cmd_threat_model(target, resolve_model(model)).await,
        Cmd::Map { target, model } => cmd_map(target, resolve_model(model)).await,
        // PLAN
        Cmd::Permute { target, model, sources, max, budget, research, yes, plan_only, concurrency } => {
            cmd_permute(target, resolve_model(model), sources, max, budget, research, yes, plan_only, concurrency).await
        }
        Cmd::Queue { sub } => cmd_queue(sub).await,
        // FIRE
        Cmd::Fire { target, model, runs, concurrency, focus, variants, models, threat_model, recon, chain, dedup, repo_map, detector, verify_top, votes, diff, resume } => {
            cmd_fire(target, resolve_model(model), runs, concurrency, focus, variants, models, threat_model, recon, chain, dedup, repo_map, detector, verify_top, votes, diff, resume).await
        }
        // TRIAGE
        Cmd::Triage { target, model, concurrency, all, votes } => cmd_verify(target, resolve_model(model), concurrency, all, votes).await,
        // MANAGE
        Cmd::Manage { target, model } => {
            let t = TargetConfig::load(&target, &targets_root())?;
            tui::run(&t, &resolve_model(model)).await
        }
        Cmd::Findings { sub } => cmd_findings(sub),
        Cmd::Seed { target, files, format, verify, model, concurrency } => {
            cmd_seed(target, files, format, verify, resolve_model(model), concurrency).await
        }
        Cmd::Ingest { target, results_dir } => cmd_ingest(target, results_dir),
        // PROVE
        Cmd::Prove { target, model, concurrency, votes } => cmd_prove(target, resolve_model(model), concurrency, votes).await,
        Cmd::Metamorphic { target, model, id, scope, concurrency, apply } => cmd_metamorphic(target, resolve_model(model), id, scope, concurrency, apply).await,
        // CHAIN
        Cmd::Chain { target, model, scope } => cmd_chain(target, resolve_model(model), scope).await,
        Cmd::Fleet { fleet, model, concurrency, votes } => cmd_fleet(fleet, resolve_model(model), concurrency, votes).await,
        // FIX
        Cmd::Fix { target, model, scope, concurrency, top } => cmd_patch(target, resolve_model(model), scope, concurrency, top).await,
        // MEASURE
        Cmd::Measure { corpus, model, concurrency, verify, votes, tol, against, gate, write_baseline } => cmd_bench(corpus, resolve_model(model), concurrency, verify, votes, tol, against, gate, write_baseline).await,
        Cmd::Tune { corpus, model, variants, verify, votes, tol, holdout, concurrency } => cmd_tune(corpus, resolve_model(model), variants, verify, votes, tol, holdout, concurrency).await,
        // output
        Cmd::Report { results_dir } => cmd_report(results_dir),
    }
}
