//! Commit archaeology (#2) — mine git history into permutation proposals.
//!
//! Two free signals every repo carries:
//!   1. **Incomplete-fix hunting** — a past *security* fix is a map to a bug class
//!      that lived here; the patch often fixes one site and misses its siblings.
//!      We propose a focused hunt around each historical fix for the variant it
//!      missed (Project-Zero-style variant analysis, automated).
//!   2. **Defect-prediction hotspots** — high-churn files harbor more bugs; we
//!      propose deep scans of the churniest code.
//!
//! The git plumbing is impure but thin; the classifier + ranking are pure and
//! unit-tested.

use crate::config::TargetConfig;
use crate::queue::{Proposal, ProposalSpec};
use std::path::Path;
use std::process::Command;

/// (substring in a commit subject, bug-class label, severity weight 0..1).
/// Ordered most-specific first so the first hit wins.
const SEC_TERMS: [(&str, &str, f64); 30] = [
    ("sql inj", "SQL injection", 0.95),
    ("sqli", "SQL injection", 0.95),
    ("command inj", "command injection", 0.97),
    ("os command", "command injection", 0.97),
    ("remote code", "RCE", 1.0),
    (" rce", "RCE", 1.0),
    ("cross-site script", "XSS", 0.8),
    ("xss", "XSS", 0.8),
    ("ssrf", "SSRF", 0.85),
    ("csrf", "CSRF", 0.6),
    ("xxe", "XXE", 0.8),
    ("path travers", "path traversal", 0.85),
    ("directory travers", "path traversal", 0.85),
    ("deserial", "unsafe deserialization", 0.9),
    ("auth bypass", "auth bypass", 0.95),
    ("authentication bypass", "auth bypass", 0.95),
    ("access control", "broken access control", 0.85),
    ("authoriz", "broken access control", 0.8),
    ("privilege escal", "privilege escalation", 0.9),
    ("idor", "IDOR", 0.8),
    ("ssti", "template injection", 0.85),
    ("template inject", "template injection", 0.85),
    ("prototype pollut", "prototype pollution", 0.8),
    ("open redirect", "open redirect", 0.5),
    ("buffer overflow", "memory safety", 0.9),
    ("use-after-free", "memory safety", 0.95),
    ("hardcoded", "secret exposure", 0.7),
    ("cve-", "known CVE", 1.0),
    ("injection", "injection", 0.78),
    ("vulnerab", "vulnerability", 0.78),
];

const FIX_VERBS: [&str; 9] = ["fix", "patch", "prevent", "sanitiz", "harden", "secur", "mitigat", "resolve", "correct"];

#[derive(Clone, Debug, PartialEq)]
pub struct FixClass {
    pub class: String,
    pub weight: f64,
}

/// Classify a commit subject as a security fix. Pure. Returns the bug class +
/// weight if a security term appears; weight is boosted when a fix verb is also
/// present (so "fix XSS" outranks "add xss fixture").
pub fn classify_fix(subject: &str) -> Option<FixClass> {
    let s = format!(" {} ", subject.to_lowercase());
    let term = SEC_TERMS.iter().find(|(t, _, _)| s.contains(t))?;
    let fixish = FIX_VERBS.iter().any(|v| s.contains(v));
    let weight = if fixish { term.2 } else { term.2 * 0.6 };
    Some(FixClass { class: term.1.to_string(), weight })
}

pub fn short_hash(h: &str) -> String {
    h.chars().take(8).collect()
}

#[derive(Clone, Debug)]
pub struct FixCommit {
    pub hash: String,
    pub subject: String,
    pub class: String,
    pub weight: f64,
    pub files: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hotspot {
    pub file: String,
    pub commits: usize,
}

fn git(source_root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(source_root).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn looks_like_source(path: &str) -> bool {
    let lower = path.to_lowercase();
    if ["test/", "tests/", "vendor/", "node_modules/", "/dist/", "/build/", ".min.", "fixture", "mock", "lock"]
        .iter()
        .any(|skip| lower.contains(skip))
    {
        return false;
    }
    matches!(
        Path::new(path).extension().and_then(|e| e.to_str()),
        Some("py" | "js" | "ts" | "jsx" | "tsx" | "java" | "go" | "rb" | "php" | "c" | "cpp" | "cc" | "h" | "rs" | "cs" | "kt" | "scala" | "swift")
    )
}

/// Count file occurrences across `git log --name-only` output (blank-line-
/// separated commit blocks). Pure.
pub fn count_files(log: &str) -> std::collections::BTreeMap<String, usize> {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for line in log.lines() {
        let f = line.trim();
        if f.is_empty() || !looks_like_source(f) {
            continue;
        }
        *counts.entry(f.to_string()).or_insert(0) += 1;
    }
    counts
}

/// Top churn hotspots (≥2 touches), most-churned first. Pure.
pub fn rank_hotspots(counts: std::collections::BTreeMap<String, usize>, top: usize) -> Vec<Hotspot> {
    let mut v: Vec<Hotspot> = counts.into_iter().filter(|(_, c)| *c >= 2).map(|(file, commits)| Hotspot { file, commits }).collect();
    v.sort_by(|a, b| b.commits.cmp(&a.commits).then(a.file.cmp(&b.file)));
    v.truncate(top);
    v
}

pub fn security_fix_commits(source_root: &Path, max_scan: usize) -> Vec<FixCommit> {
    let log = match git(source_root, &["log", &format!("-n{max_scan}"), "--format=%H%x09%s"]) {
        Some(l) => l,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in log.lines() {
        let (hash, subject) = match line.split_once('\t') {
            Some(x) => x,
            None => continue,
        };
        if let Some(fc) = classify_fix(subject) {
            let files = git(source_root, &["show", "--name-only", "--format=", hash])
                .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| looks_like_source(l)).collect::<Vec<_>>())
                .unwrap_or_default();
            out.push(FixCommit { hash: hash.to_string(), subject: subject.to_string(), class: fc.class, weight: fc.weight, files });
        }
    }
    out
}

pub fn churn_hotspots(source_root: &Path, max_scan: usize, top: usize) -> Vec<Hotspot> {
    match git(source_root, &["log", &format!("-n{max_scan}"), "--name-only", "--format="]) {
        Some(log) => rank_hotspots(count_files(&log), top),
        None => Vec::new(),
    }
}

/// Build proposals from git archaeology. Newest fixes and churniest files rank
/// highest; everything is capped to `max` to keep the queue legible.
pub fn propose(target: &TargetConfig, max: usize) -> Vec<Proposal> {
    let root = &target.source_root;
    let mut props: Vec<Proposal> = Vec::new();

    let fixes = security_fix_commits(root, 300);
    let n = fixes.len().max(1) as f64;
    for (i, fc) in fixes.iter().enumerate() {
        // newest first in git order → linear recency 1.0 → 0.5
        let recency = 1.0 - 0.5 * (i as f64 / n);
        let files_disp = if fc.files.is_empty() {
            "(the patch's files could not be listed — locate them by the class)".to_string()
        } else {
            fc.files.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
        };
        let focus = format!(
            "INCOMPLETE-FIX HUNT. Commit {} fixed a {} (\"{}\"). Re-examine the files it touched — {} — and the code they call. Hunt for the SAME bug class in places the original patch did NOT cover: sibling endpoints, similar sinks, copy-pasted blocks, the same helper used elsewhere. Find the variant the fix missed.",
            short_hash(&fc.hash),
            fc.class,
            fc.subject.chars().take(90).collect::<String>(),
            files_disp,
        );
        props.push(Proposal::new(
            "commit-archaeology",
            format!("Variant-hunt around the {} fix ({})", fc.class, short_hash(&fc.hash)),
            format!("Commit {} touched {} source file(s); a past security fix is a prime variant-analysis target.", short_hash(&fc.hash), fc.files.len()),
            ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
            fc.weight * (0.6 + 0.4 * recency),
        ));
    }

    let hotspots = churn_hotspots(root, 300, max);
    let max_churn = hotspots.first().map(|h| h.commits).unwrap_or(1) as f64;
    for h in hotspots {
        let focus = format!(
            "CHURN HOTSPOT. Concentrate entirely on {} and the code it directly touches — it changed in {} of the last 300 commits, and high-churn code statistically harbors more defects. Go deep here.",
            h.file, h.commits
        );
        props.push(Proposal::new(
            "commit-archaeology",
            format!("Deep-scan churn hotspot {} ({} commits)", h.file, h.commits),
            format!("{} is among the most-churned files; defect density tracks churn.", h.file),
            ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
            0.45 * (h.commits as f64 / max_churn),
        ));
    }

    props.sort_by(|a, b| b.yield_score.partial_cmp(&a.yield_score).unwrap_or(std::cmp::Ordering::Equal));
    props.truncate(max);
    props
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_fix_detects_security_classes() {
        assert_eq!(classify_fix("Fix SQL injection in user search").unwrap().class, "SQL injection");
        assert_eq!(classify_fix("patch XSS in comment render").unwrap().class, "XSS");
        assert_eq!(classify_fix("Resolve CVE-2021-1234 in parser").unwrap().class, "known CVE");
        assert_eq!(classify_fix("prevent path traversal on download").unwrap().class, "path traversal");
        // not security
        assert!(classify_fix("Bump dependency versions").is_none());
        assert!(classify_fix("Refactor the rendering pipeline").is_none());
    }

    #[test]
    fn fix_verb_boosts_weight() {
        let with_verb = classify_fix("fix XSS in profile").unwrap().weight;
        let without = classify_fix("add xss sample to corpus").unwrap().weight;
        assert!(with_verb > without, "{with_verb} should beat {without}");
    }

    #[test]
    fn count_and_rank_hotspots() {
        // app.py touched 3×, db.py 2×, README once, a test ignored
        let log = "app.py\ndb.py\n\napp.py\ntests/test_app.py\n\napp.py\ndb.py\nREADME.md\n";
        let counts = count_files(log);
        assert_eq!(counts.get("app.py"), Some(&3));
        assert_eq!(counts.get("db.py"), Some(&2));
        assert_eq!(counts.get("README.md"), None); // not source
        assert_eq!(counts.get("tests/test_app.py"), None); // test path filtered
        let ranked = rank_hotspots(counts, 10);
        assert_eq!(ranked[0], Hotspot { file: "app.py".into(), commits: 3 });
        assert_eq!(ranked[1], Hotspot { file: "db.py".into(), commits: 2 });
        assert_eq!(ranked.len(), 2); // README (1) below the ≥2 threshold
    }

    #[test]
    fn short_hash_is_eight() {
        assert_eq!(short_hash("0123456789abcdef"), "01234567");
    }
}
