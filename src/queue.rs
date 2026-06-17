//! The permutation queue — the human gate that makes signal-driven permutation
//! affordable.
//!
//! Generators (commit archaeology, threat-model, threat-intel, evolution) never
//! fire. They **propose**: each candidate permutation arrives as a `Proposal`
//! with a yield score and a **cost estimate**, and lands here. You walk the queue
//! — approve, skip, defer — and only approved proposals are scheduled and fired,
//! under a hard budget cap. Every completed run feeds its *actual* cost back, so
//! the estimates self-calibrate.
//!
//! Canonical state: `targets/<t>/.cannon/queue.json`. This module is pure and
//! deterministic (no agents, no salvo) and is unit-tested end to end.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Statuses a proposal moves through. "approved" == scheduled to run.
pub const PROPOSAL_STATUSES: [&str; 7] = ["proposed", "approved", "deferred", "skipped", "running", "done", "failed"];

/// The four signal sources (+ manual), used for display + dedup grouping.
pub const SOURCES: [&str; 5] = ["commit-archaeology", "threat-model", "threat-intel", "evolution", "manual"];

fn one() -> usize {
    1
}
fn default_cost_per_round() -> f64 {
    // Prior for one find-agent round before any real run calibrates it. A round
    // with cross-file taint resolution runs $0.5–$3 depending on model/repo, so a
    // mid estimate beats a tiny one (which would let the gate over-approve on day
    // one). `record_result` pulls this toward the observed rate after each fire.
    0.75
}

/// The salvo parameters a proposal would fire — expands to rounds exactly like
/// `permute::build_matrix` (focus × variant × model × runs).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ProposalSpec {
    pub focus_areas: Vec<String>,
    #[serde(default)]
    pub variants: Vec<String>, // empty → ["default"]
    #[serde(default)]
    pub models: Vec<String>, // empty → the driver's default model
    #[serde(default = "one")]
    pub runs: usize,
    /// run the adversarial verifier after the salvo (≈ doubles cost)
    #[serde(default)]
    pub verify: bool,
    #[serde(default)]
    pub votes: usize, // 0 → default
}

impl ProposalSpec {
    /// Round count = |focus| × |variant| × |model| × runs (matches the matrix).
    pub fn rounds(&self) -> usize {
        self.focus_areas.len().max(1) * self.variants.len().max(1) * self.models.len().max(1) * self.runs.max(1)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String, // P-001
    /// one of SOURCES
    pub source: String,
    pub title: String,
    #[serde(default)]
    pub rationale: String,
    pub spec: ProposalSpec,
    /// generator's priority — higher fires sooner
    pub yield_score: f64,
    #[serde(default)]
    pub est_rounds: usize,
    #[serde(default)]
    pub est_cost: f64,
    /// one of PROPOSAL_STATUSES
    pub status: String,
    #[serde(default)]
    pub created: String,
    /// a free-text user suggestion that seeded / re-ranked this proposal
    #[serde(default)]
    pub seeded_by: Option<String>,
    // ── outcome, filled after execution ──────────────────────────────────────
    #[serde(default)]
    pub actual_cost: Option<f64>,
    #[serde(default)]
    pub findings: Option<usize>,
    #[serde(default)]
    pub confirmed: Option<usize>,
    #[serde(default)]
    pub results_dir: Option<String>,
}

impl Proposal {
    /// Construct an un-queued proposal (id/estimate/status are filled by `Queue::add`).
    pub fn new(source: &str, title: impl Into<String>, rationale: impl Into<String>, spec: ProposalSpec, yield_score: f64) -> Proposal {
        Proposal {
            id: String::new(),
            source: source.into(),
            title: title.into(),
            rationale: rationale.into(),
            spec,
            yield_score,
            est_rounds: 0,
            est_cost: 0.0,
            status: String::new(),
            created: String::new(),
            seeded_by: None,
            actual_cost: None,
            findings: None,
            confirmed: None,
            results_dir: None,
        }
    }

    /// A stable identity for dedup — same source + same firing target.
    pub fn dedup_key(&self) -> String {
        format!("{}|{}|{:?}", self.source, self.title.to_lowercase(), self.spec.focus_areas)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Queue {
    #[serde(default)]
    pub proposals: Vec<Proposal>,
    #[serde(default = "one")]
    pub next_id: usize,
    /// rolling $/round, calibrated from real runs (the self-tuning estimate)
    #[serde(default = "default_cost_per_round")]
    pub cost_per_round: f64,
    /// hard cap on cumulative (spent + approved-but-unrun) cost; None = no cap
    #[serde(default)]
    pub budget_cap: Option<f64>,
    /// cumulative ACTUAL $ spent by executed proposals
    #[serde(default)]
    pub spent: f64,
}

impl Default for Queue {
    fn default() -> Self {
        Queue { proposals: Vec::new(), next_id: 1, cost_per_round: default_cost_per_round(), budget_cap: None, spent: 0.0 }
    }
}

impl Queue {
    pub fn json_path(target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(".cannon").join("queue.json")
    }

    pub fn load(target_dir: &Path) -> Queue {
        std::fs::read_to_string(Self::json_path(target_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn lock_path(target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(".cannon").join(".queue.lock")
    }

    pub fn save(&self, target_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(target_dir.join(".cannon"))?;
        let _lock = crate::lock::FileLock::acquire(Self::lock_path(target_dir))?;
        let j = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        crate::lock::write_atomic(&Self::json_path(target_dir), j.as_bytes())
    }

    /// Estimate (rounds, $) for a spec at the current calibrated rate. Verify
    /// roughly doubles the work (a verifier pass per finding).
    pub fn estimate(&self, spec: &ProposalSpec) -> (usize, f64) {
        let rounds = spec.rounds();
        let mult = if spec.verify { 2.0 } else { 1.0 };
        (rounds, rounds as f64 * self.cost_per_round * mult)
    }

    /// Add a proposal (assigning id, estimate, status). Returns its id, or None
    /// if a near-identical proposal already exists (dedup).
    pub fn add(&mut self, mut p: Proposal, now: &str) -> Option<String> {
        let key = p.dedup_key();
        if self.proposals.iter().any(|x| x.dedup_key() == key && x.status != "skipped") {
            return None;
        }
        let (rounds, cost) = self.estimate(&p.spec);
        p.id = format!("P-{:03}", self.next_id);
        self.next_id += 1;
        p.est_rounds = rounds;
        p.est_cost = cost;
        p.status = "proposed".into();
        if p.created.is_empty() {
            p.created = now.to_string();
        }
        let id = p.id.clone();
        self.proposals.push(p);
        Some(id)
    }

    pub fn by_id_mut(&mut self, id: &str) -> Option<&mut Proposal> {
        self.proposals.iter_mut().find(|p| p.id.eq_ignore_ascii_case(id))
    }

    /// Proposals awaiting a decision, best-yield first.
    pub fn pending(&self) -> Vec<&Proposal> {
        let mut v: Vec<&Proposal> = self.proposals.iter().filter(|p| p.status == "proposed").collect();
        v.sort_by(|a, b| b.yield_score.partial_cmp(&a.yield_score).unwrap_or(std::cmp::Ordering::Equal).then(a.id.cmp(&b.id)));
        v
    }

    /// Approved-but-unrun proposals, best-yield first (the run order).
    pub fn approved(&self) -> Vec<&Proposal> {
        let mut v: Vec<&Proposal> = self.proposals.iter().filter(|p| p.status == "approved").collect();
        v.sort_by(|a, b| b.yield_score.partial_cmp(&a.yield_score).unwrap_or(std::cmp::Ordering::Equal).then(a.id.cmp(&b.id)));
        v
    }

    /// $ already spent plus $ committed to approved-but-unrun proposals.
    pub fn committed(&self) -> f64 {
        self.spent + self.proposals.iter().filter(|p| p.status == "approved").map(|p| p.est_cost).sum::<f64>()
    }

    /// Would approving `est_cost` more breach the cap? (no cap → never).
    pub fn would_exceed_budget(&self, est_cost: f64) -> bool {
        matches!(self.budget_cap, Some(cap) if self.committed() + est_cost > cap + 1e-9)
    }

    /// Approve a proposal for scheduling, unless it would breach the budget cap.
    /// Returns Err with a message if blocked.
    pub fn approve(&mut self, id: &str) -> Result<(), String> {
        let est = self.by_id_mut(id).map(|p| p.est_cost).ok_or_else(|| format!("no proposal {id}"))?;
        if self.would_exceed_budget(est) {
            return Err(format!(
                "approving {id} (${est:.2}) would breach the budget cap ${:.2} (committed ${:.2})",
                self.budget_cap.unwrap_or(0.0),
                self.committed()
            ));
        }
        if let Some(p) = self.by_id_mut(id) {
            p.status = "approved".into();
        }
        Ok(())
    }

    pub fn set_status(&mut self, id: &str, status: &str) -> Result<(), String> {
        if !PROPOSAL_STATUSES.contains(&status) {
            return Err(format!("unknown status '{status}'"));
        }
        match self.by_id_mut(id) {
            Some(p) => {
                p.status = status.into();
                Ok(())
            }
            None => Err(format!("no proposal {id}")),
        }
    }

    /// Record a finished run: store outcome, add to spent, and **calibrate** the
    /// $/round estimate toward the observed rate (EMA, weight 0.3).
    pub fn record_result(&mut self, id: &str, actual_cost: f64, findings: usize, confirmed: usize, results_dir: &str) {
        let rounds = self.by_id_mut(id).map(|p| p.est_rounds.max(1)).unwrap_or(1);
        if let Some(p) = self.by_id_mut(id) {
            p.status = "done".into();
            p.actual_cost = Some(actual_cost);
            p.findings = Some(findings);
            p.confirmed = Some(confirmed);
            p.results_dir = Some(results_dir.to_string());
        }
        self.spent += actual_cost;
        if actual_cost > 0.0 {
            let observed = actual_cost / rounds as f64;
            self.cost_per_round = 0.7 * self.cost_per_round + 0.3 * observed;
        }
    }

    /// Drop everything that's been decided (done/skipped/failed), keeping the
    /// live queue (proposed/approved/deferred). Returns how many were cleared.
    pub fn prune_decided(&mut self) -> usize {
        let before = self.proposals.len();
        self.proposals.retain(|p| !["done", "skipped", "failed"].contains(&p.status.as_str()));
        before - self.proposals.len()
    }

    pub fn counts(&self) -> std::collections::BTreeMap<String, usize> {
        let mut m = std::collections::BTreeMap::new();
        for p in &self.proposals {
            *m.entry(p.status.clone()).or_insert(0) += 1;
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(focus: &[&str], runs: usize, verify: bool) -> ProposalSpec {
        ProposalSpec { focus_areas: focus.iter().map(|s| s.to_string()).collect(), variants: vec![], models: vec![], runs, verify, votes: 0 }
    }

    fn prop(source: &str, title: &str, focus: &[&str], yield_score: f64) -> Proposal {
        Proposal {
            id: String::new(),
            source: source.into(),
            title: title.into(),
            rationale: String::new(),
            spec: spec(focus, 1, false),
            yield_score,
            est_rounds: 0,
            est_cost: 0.0,
            status: String::new(),
            created: String::new(),
            seeded_by: None,
            actual_cost: None,
            findings: None,
            confirmed: None,
            results_dir: None,
        }
    }

    #[test]
    fn rounds_match_the_matrix_cardinality() {
        let s = ProposalSpec { focus_areas: vec!["a".into(), "b".into()], variants: vec!["x".into(), "y".into()], models: vec!["m".into()], runs: 3, verify: false, votes: 0 };
        assert_eq!(s.rounds(), 2 * 2 * 1 * 3);
        assert_eq!(spec(&[], 1, false).rounds(), 1); // empty focus still ≥1
    }

    #[test]
    fn add_assigns_id_estimate_and_dedups() {
        let mut q = Queue::default();
        let id = q.add(prop("threat-model", "scan flow A", &["a.py"], 1.0), "now").unwrap();
        assert_eq!(id, "P-001");
        let p = &q.proposals[0];
        assert_eq!(p.est_rounds, 1);
        assert!((p.est_cost - q.cost_per_round).abs() < 1e-9);
        assert_eq!(p.status, "proposed");
        // identical proposal is deduped
        assert!(q.add(prop("threat-model", "scan flow A", &["a.py"], 1.0), "now").is_none());
        assert_eq!(q.proposals.len(), 1);
    }

    #[test]
    fn verify_doubles_the_estimate() {
        let q = Queue::default();
        let (_, plain) = q.estimate(&spec(&["a"], 2, false));
        let (_, verified) = q.estimate(&spec(&["a"], 2, true));
        assert!((verified - 2.0 * plain).abs() < 1e-9);
    }

    #[test]
    fn pending_is_sorted_by_yield() {
        let mut q = Queue::default();
        q.add(prop("a", "low", &["l"], 0.2), "now");
        q.add(prop("a", "high", &["h"], 0.9), "now");
        q.add(prop("a", "mid", &["m"], 0.5), "now");
        let order: Vec<&str> = q.pending().iter().map(|p| p.title.as_str()).collect();
        assert_eq!(order, vec!["high", "mid", "low"]);
    }

    #[test]
    fn budget_cap_blocks_overspend() {
        let mut q = Queue { budget_cap: Some(0.10), cost_per_round: 0.06, ..Default::default() };
        let a = q.add(prop("a", "one", &["x"], 1.0), "now").unwrap(); // est 0.06
        let b = q.add(prop("a", "two", &["y"], 1.0), "now").unwrap(); // est 0.06
        assert!(q.approve(&a).is_ok()); // committed 0.06 ≤ 0.10
        // second approval → committed 0.12 > 0.10 → blocked
        assert!(q.approve(&b).is_err());
        assert_eq!(q.by_id_mut(&b).unwrap().status, "proposed");
    }

    #[test]
    fn record_result_calibrates_cost_per_round() {
        let mut q = Queue { cost_per_round: 0.06, ..Default::default() };
        let id = q.add(prop("a", "run", &["x", "y"], 1.0), "now").unwrap(); // 2 rounds
        q.approve(&id).unwrap();
        // actual $0.40 over 2 rounds → observed $0.20/round; EMA 0.7*0.06+0.3*0.20
        q.record_result(&id, 0.40, 5, 2, "results/x");
        let expected = 0.7 * 0.06 + 0.3 * 0.20;
        assert!((q.cost_per_round - expected).abs() < 1e-9);
        assert!((q.spent - 0.40).abs() < 1e-9);
        assert_eq!(q.by_id_mut(&id).unwrap().status, "done");
        assert_eq!(q.by_id_mut(&id).unwrap().confirmed, Some(2));
    }

    #[test]
    fn committed_counts_spent_plus_approved() {
        let mut q = Queue { cost_per_round: 0.10, ..Default::default() };
        let a = q.add(prop("a", "one", &["x"], 1.0), "now").unwrap();
        let b = q.add(prop("a", "two", &["y"], 1.0), "now").unwrap();
        q.approve(&a).unwrap();
        q.approve(&b).unwrap();
        assert!((q.committed() - 0.20).abs() < 1e-9); // two approved × 0.10
        q.record_result(&a, 0.15, 1, 1, "r"); // a done: spent 0.15, b still approved 0.10
        assert!((q.committed() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn prune_keeps_live_drops_decided() {
        let mut q = Queue::default();
        let a = q.add(prop("a", "keep", &["x"], 1.0), "now").unwrap();
        let b = q.add(prop("a", "drop", &["y"], 1.0), "now").unwrap();
        q.set_status(&b, "skipped").unwrap();
        let _ = a;
        assert_eq!(q.prune_decided(), 1);
        assert_eq!(q.proposals.len(), 1);
        assert_eq!(q.proposals[0].title, "keep");
    }
}
