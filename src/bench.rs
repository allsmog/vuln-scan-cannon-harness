//! Benchmark scoring — match detected findings against ground-truth labels and
//! compute precision / recall / F1. The scorer is pure and deterministic; the
//! `cannon bench` command (cli) runs scans over a labeled corpus and feeds it.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
pub struct Label {
    pub file: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // human-readable label annotation
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Detected {
    pub file: String,
    pub line: Option<u32>,
    pub cwe: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct BenchScore {
    pub tp: usize,
    pub fp: usize,
    pub fn_: usize,
}

impl BenchScore {
    pub fn add(&mut self, other: &BenchScore) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_ += other.fn_;
    }
    pub fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 { 1.0 } else { self.tp as f64 / d as f64 }
    }
    pub fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 { 1.0 } else { self.tp as f64 / d as f64 }
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
    }
}

fn basename(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

fn cwe_num(c: &Option<String>) -> Option<String> {
    c.as_ref().and_then(|x| {
        let d: String = x.chars().filter(|ch| ch.is_ascii_digit()).collect();
        let d = d.trim_start_matches('0');
        if d.is_empty() { None } else { Some(d.to_string()) }
    })
}

fn matches(d: &Detected, l: &Label, tol: u32) -> bool {
    if basename(&d.file) != basename(&l.file) {
        return false;
    }
    if let (Some(dl), Some(ll)) = (d.line, l.line) {
        if (dl as i64 - ll as i64).abs() > tol as i64 {
            return false;
        }
    }
    match (cwe_num(&d.cwe), cwe_num(&l.cwe)) {
        (Some(a), Some(b)) => a == b,
        _ => true, // if either side lacks a CWE, don't penalize on class
    }
}

/// Greedy one-to-one match of detections to labels.
pub fn score(detected: &[Detected], labels: &[Label], tol: u32) -> BenchScore {
    let mut matched = vec![false; labels.len()];
    let (mut tp, mut fp) = (0, 0);
    for d in detected {
        let hit = labels
            .iter()
            .enumerate()
            .find(|(i, l)| !matched[*i] && matches(d, l, tol))
            .map(|(i, _)| i);
        match hit {
            Some(i) => {
                matched[i] = true;
                tp += 1;
            }
            None => fp += 1,
        }
    }
    let fn_ = matched.iter().filter(|m| !**m).count();
    BenchScore { tp, fp, fn_ }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(file: &str, line: u32, cwe: &str) -> Detected {
        Detected { file: file.into(), line: Some(line), cwe: Some(cwe.into()) }
    }
    fn l(file: &str, line: u32, cwe: &str) -> Label {
        Label { file: file.into(), line: Some(line), cwe: Some(cwe.into()), note: None }
    }

    #[test]
    fn exact_match_is_tp() {
        let s = score(&[d("app.py", 30, "CWE-89")], &[l("app.py", 30, "CWE-89")], 3);
        assert_eq!((s.tp, s.fp, s.fn_), (1, 0, 0));
        assert!((s.f1() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn line_tolerance_and_basename() {
        // different dir prefix, line off by 2, within tol
        let s = score(&[d("src/app.py", 32, "CWE-89")], &[l("app.py", 30, "CWE-89")], 3);
        assert_eq!(s.tp, 1);
        // off by 10, outside tol → not matched
        let s2 = score(&[d("app.py", 45, "CWE-89")], &[l("app.py", 30, "CWE-89")], 3);
        assert_eq!((s2.tp, s2.fp, s2.fn_), (0, 1, 1));
    }

    #[test]
    fn cwe_mismatch_not_matched() {
        let s = score(&[d("app.py", 30, "CWE-22")], &[l("app.py", 30, "CWE-89")], 3);
        assert_eq!((s.tp, s.fp, s.fn_), (0, 1, 1));
    }

    #[test]
    fn missing_and_extra() {
        let detected = vec![d("a.py", 1, "CWE-89"), d("z.py", 9, "CWE-78")]; // z is a FP
        let labels = vec![l("a.py", 1, "CWE-89"), l("b.py", 2, "CWE-22")]; // b is missed
        let s = score(&detected, &labels, 2);
        assert_eq!((s.tp, s.fp, s.fn_), (1, 1, 1));
        assert!((s.precision() - 0.5).abs() < 1e-9);
        assert!((s.recall() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn one_detection_matches_one_label() {
        // two detections at the same spot shouldn't both claim one label
        let s = score(&[d("a.py", 1, "CWE-89"), d("a.py", 1, "CWE-89")], &[l("a.py", 1, "CWE-89")], 2);
        assert_eq!((s.tp, s.fp), (1, 1));
    }
}
