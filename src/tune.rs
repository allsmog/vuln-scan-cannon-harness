//! Benchmark-as-fitness — turn `measure` into an optimizer and a regression gate.
//!
//! The harness's whole premise is permuting/mutating prompts; this closes the
//! loop by scoring prompt variants against labeled ground truth and keeping the
//! best — with an honest train/test split so a "win" isn't just overfitting the
//! corpus, and a gate so a prompt edit can't silently tank precision in CI.
//!
//! This module is the deterministic core (split / select / gate / baseline);
//! `cmd_tune` in main drives the actual scans over the splits.

use crate::bench::BenchScore;
use serde::{Deserialize, Serialize};

/// Deterministically split corpus items into (train, test). `holdout` is the
/// fraction routed to test; the split is index-striped (no RNG) so it is stable
/// across runs and resumable — every `round(1/holdout)`-th item goes to test.
pub fn split_corpus<T: Clone>(items: &[T], holdout: f64) -> (Vec<T>, Vec<T>) {
    let h = holdout.clamp(0.0, 1.0);
    if h <= 0.0 {
        return (items.to_vec(), Vec::new());
    }
    if h >= 1.0 {
        return (Vec::new(), items.to_vec());
    }
    let step = (1.0 / h).round().max(1.0) as usize;
    let mut train = Vec::new();
    let mut test = Vec::new();
    for (i, it) in items.iter().enumerate() {
        if (i + 1) % step == 0 {
            test.push(it.clone());
        } else {
            train.push(it.clone());
        }
    }
    (train, test)
}

/// Pick the best variant by F1, tie-broken by precision, then name (ascending, so
/// the choice is stable and reproducible). None on empty input.
pub fn select_best(results: &[(String, BenchScore)]) -> Option<String> {
    results
        .iter()
        .max_by(|a, b| {
            a.1.f1()
                .partial_cmp(&b.1.f1())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1.precision().partial_cmp(&b.1.precision()).unwrap_or(std::cmp::Ordering::Equal))
                // smaller name wins ties → reverse so `max` selects it
                .then(b.0.cmp(&a.0))
        })
        .map(|(n, _)| n.clone())
}

/// Regression gate: pass iff `current` is within `margin` of (or above) the
/// `baseline` F1. Returns true on pass.
pub fn gate(current_f1: f64, baseline_f1: f64, margin: f64) -> bool {
    current_f1 + margin >= baseline_f1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub f1: f64,
    pub precision: f64,
    pub recall: f64,
    #[serde(default)]
    pub note: String,
}

impl Baseline {
    pub fn from_score(s: &BenchScore) -> Self {
        Baseline { f1: s.f1(), precision: s.precision(), recall: s.recall(), note: String::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(tp: usize, fp: usize, fn_: usize) -> BenchScore {
        BenchScore { tp, fp, fn_ }
    }

    #[test]
    fn split_is_deterministic_and_striped() {
        let items: Vec<i32> = (0..10).collect();
        let (tr, te) = split_corpus(&items, 0.5);
        assert_eq!(te, vec![1, 3, 5, 7, 9]);
        assert_eq!(tr, vec![0, 2, 4, 6, 8]);
        // identical on a second call (resumable)
        assert_eq!(split_corpus(&items, 0.5), (tr, te));
        // a third holdout → roughly 1/3 to test
        let (_t3, te3) = split_corpus(&items, 0.34);
        assert_eq!(te3, vec![2, 5, 8]);
        // degenerate ratios
        assert!(split_corpus(&items, 0.0).1.is_empty());
        assert!(split_corpus(&items, 1.0).0.is_empty());
    }

    #[test]
    fn select_best_prefers_higher_f1_then_name() {
        let hi = s(9, 1, 1); // f1 0.9
        let lo = s(5, 5, 5); // f1 0.5
        assert_eq!(select_best(&[("lo".into(), lo), ("hi".into(), hi.clone())]).as_deref(), Some("hi"));
        // identical scores → alphabetical first
        assert_eq!(select_best(&[("zebra".into(), hi.clone()), ("alpha".into(), hi)]).as_deref(), Some("alpha"));
        assert_eq!(select_best(&[]), None);
    }

    #[test]
    fn select_best_breaks_f1_tie_on_precision() {
        let bal = s(4, 4, 4); // p .5  r .5  f1 .5
        let prec = s(4, 2, 6); // p .667 r .4 f1 .5
        assert!((bal.f1() - prec.f1()).abs() < 1e-9);
        assert_eq!(select_best(&[("bal".into(), bal), ("prec".into(), prec)]).as_deref(), Some("prec"));
    }

    #[test]
    fn gate_passes_within_margin_fails_below() {
        assert!(gate(0.74, 0.75, 0.02)); // small dip, tolerated
        assert!(gate(0.80, 0.75, 0.02)); // improvement
        assert!(gate(0.75, 0.75, 0.0)); // exactly equal
        assert!(!gate(0.70, 0.75, 0.02)); // real regression
    }
}
