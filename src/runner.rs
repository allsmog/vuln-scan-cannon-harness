//! run_salvo — the ONLY orchestration seam.
//!
//! A bounded async fan-out over the permutation matrix, each round checkpointed
//! to run_NNN/result.json, with --resume skipping terminal rounds. No broker,
//! no DB: swap only this function's body for multi-machine fan-out.

use crate::artifacts::RoundResult;
use crate::config::TargetConfig;
use crate::detector;
use crate::permute::Spec;
use crate::ui::color;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub fn round_dir(results_dir: &Path, idx: usize) -> PathBuf {
    results_dir.join(format!("run_{idx:03}"))
}

pub fn load_rounds(results_dir: &Path) -> Vec<RoundResult> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(results_dir) {
        let mut dirs: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("run_"))
                    .unwrap_or(false)
            })
            .collect();
        dirs.sort();
        for d in dirs {
            if let Ok(s) = std::fs::read_to_string(d.join("result.json")) {
                if let Ok(r) = serde_json::from_str::<RoundResult>(&s) {
                    out.push(r);
                }
            }
        }
    }
    out
}

pub async fn run_salvo(
    target: &TargetConfig,
    specs: &[Spec],
    results_dir: &Path,
    context_block: &str,
    concurrency: usize,
    resume: bool,
) -> Vec<RoundResult> {
    std::fs::create_dir_all(results_dir).ok();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let target = Arc::new(target.clone());
    let ctx = Arc::new(context_block.to_string());
    let results_dir = results_dir.to_path_buf();

    let mut set: JoinSet<(usize, RoundResult)> = JoinSet::new();
    let mut results: BTreeMap<usize, RoundResult> = BTreeMap::new();
    let mut skipped = 0usize;

    for spec in specs {
        let ckpt = round_dir(&results_dir, spec.round_idx).join("result.json");
        if resume && ckpt.is_file() {
            if let Ok(s) = std::fs::read_to_string(&ckpt) {
                if let Ok(prev) = serde_json::from_str::<RoundResult>(&s) {
                    if prev.is_terminal() && prev.status != "agent_failed" {
                        results.insert(spec.round_idx, prev);
                        skipped += 1;
                        continue;
                    }
                }
            }
        }

        let sem = sem.clone();
        let target = target.clone();
        let ctx = ctx.clone();
        let spec = spec.clone();
        let results_dir = results_dir.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let out_dir = round_dir(&results_dir, spec.round_idx);
            println!(
                "{}",
                color(
                    &format!(
                        "  ▸ firing {}  [{} · {}]",
                        spec.label,
                        spec.focus_area.clone().unwrap_or_else(|| "no focus".into()),
                        spec.model
                    ),
                    "cannon"
                )
            );
            let rr = detector::run_round(&target, &spec, &ctx, &out_dir, Some(format!("  [{}]", spec.label))).await;

            std::fs::create_dir_all(&out_dir).ok();
            if let Ok(j) = serde_json::to_string_pretty(&rr) {
                let tmp = out_dir.join("result.json.tmp");
                if std::fs::write(&tmp, &j).is_ok() {
                    let _ = std::fs::rename(&tmp, out_dir.join("result.json"));
                }
            }

            let nf = rr.findings.len();
            let tag = if nf > 0 {
                color(&format!("{nf} finding(s)"), "bold")
            } else {
                "no findings".to_string()
            };
            let col = if rr.status == "error" || rr.status == "agent_failed" { "red" } else { "report" };
            println!("{}", color(&format!("  ✓ {}: {} — {}", spec.label, rr.status, tag), col));
            (spec.round_idx, rr)
        });
    }

    while let Some(res) = set.join_next().await {
        if let Ok((idx, rr)) = res {
            results.insert(idx, rr);
        }
    }
    if skipped > 0 {
        println!("{}", color(&format!("  [resume] skipped {skipped} already-terminal round(s)"), "dim"));
    }
    results.into_values().collect()
}
