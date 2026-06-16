//! Data contracts for the cannon pipeline (ported from the verified Python build).
//!
//!   Finding         — one issue claimed by one find-agent (one round)
//!   RoundResult     — one salvo round's outcome (checkpoint of record on disk)
//!   AccumulatedFinding — Findings unioned + deduped across rounds (corroboration)
//!   Verdict         — the adversarial verifier's call on a deduped finding
//!   TriagedFinding  — accumulated + verdict + rank score
//!   Chain           — a multi-step attack composed from confirmed findings

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
pub const TERMINAL_STATUSES: [&str; 4] = ["completed", "no_findings", "agent_failed", "error"];

pub fn norm_severity(s: &str) -> String {
    let up = s.trim().to_uppercase();
    for sev in SEVERITIES {
        if up.starts_with(sev) {
            return sev.to_string();
        }
    }
    "INFO".to_string()
}

/// Higher = more severe (for sorting).
pub fn sev_rank(s: &str) -> i32 {
    let n = norm_severity(s);
    let idx = SEVERITIES.iter().position(|&x| x == n).unwrap_or(SEVERITIES.len() - 1);
    (SEVERITIES.len() - idx) as i32
}

fn sev_weight(s: &str) -> f64 {
    match norm_severity(s).as_str() {
        "CRITICAL" => 4.0,
        "HIGH" => 3.0,
        "MEDIUM" => 2.0,
        "LOW" => 1.0,
        _ => 0.5,
    }
}

pub fn slugify(s: &str, n: usize) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    trimmed.chars().take(n).collect()
}

fn basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

// ──────────────────────────────────────────────────────────────────────────────
// Taint path — agentic interprocedural taint resolution
// ──────────────────────────────────────────────────────────────────────────────

/// One hop in a cross-file taint path the finder resolved by following symbols
/// (it has Read/Grep/Glob, so it can open callees in other files and read what
/// they actually do). `role` ∈ {source, propagator, sanitizer, sink, constant}.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintStep {
    pub file: String,
    #[serde(default)]
    pub line: Option<u32>,
    pub role: String,
    #[serde(default)]
    pub note: String,
}

/// Canonicalize the finder's taint outcome to one token:
///   reachable     — untrusted source reaches the sink unbroken          → report
///   exposure      — config/secret exposure with no input→sink path        → report
///   sanitized     — a validator/encoder neutralizes it on the path        → self-refuted
///   constant      — the value is constant / not attacker-controlled       → self-refuted
///   not_reachable — the sink is unreachable from any untrusted entry      → self-refuted
///   unresolved    — could not fully trace                                 → report (cautiously)
///
/// Order matters: exposure → constant → sanitized → not_reachable → reachable,
/// so "not reachable" is never misread as "reachable".
pub fn norm_taint_status(s: &str) -> Option<String> {
    let t = s.trim().to_lowercase();
    if t.is_empty() {
        return None;
    }
    let canon = if t.contains("exposure") || t.contains("secret") || t.contains("config") || t.contains("n/a") || t.contains("not applicable") {
        "exposure"
    } else if t.contains("constant") || t.contains("not attacker") || t.contains("not_attacker") || t.contains("fixed value") || t.contains("hardcoded value") {
        "constant"
    } else if t.contains("saniti") || t.contains("validat") || t.contains("escap") || t.contains("neutral") || t.contains("encoded") {
        "sanitized"
    } else if t.contains("unreach") || t.contains("not reach") || t.contains("not_reach") || t.contains("dead code") || t.contains("no path") {
        "not_reachable"
    } else if t.contains("reach") || t.contains("tainted") || t.contains("exploitable") {
        "reachable"
    } else {
        "unresolved"
    };
    Some(canon.to_string())
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub file: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub exploit_premise: String,
    #[serde(default)]
    pub focus_area: Option<String>,
    #[serde(default)]
    pub round_label: Option<String>,
    /// Cross-file taint path the finder resolved by following symbols.
    #[serde(default)]
    pub taint_path: Vec<TaintStep>,
    /// The finder's resolution outcome (see `norm_taint_status`).
    #[serde(default)]
    pub taint_status: Option<String>,
}

impl Finding {
    /// Stable identity for cross-round dedup: (basename, line-bucket, class).
    pub fn signature(&self) -> String {
        let base = if self.file.is_empty() { "?".to_string() } else { basename(&self.file) };
        // Exact line: a finding is at a specific location. Same-line reports across
        // rounds still merge (corroboration); distinct findings on adjacent lines
        // (e.g. two secrets) stay separate. Near-line near-dups are handled by the
        // optional semantic dedup stage rather than by coarse line bucketing.
        let bucket: i64 = match self.line {
            Some(l) => l as i64,
            None => -1,
        };
        let cls = match &self.cwe {
            Some(c) if !c.trim().is_empty() => {
                let digits: String = c.chars().filter(|ch| ch.is_ascii_digit()).collect();
                // Normalize CWE numbers so "CWE-089" and "CWE-89" collide.
                let trimmed = digits.trim_start_matches('0');
                if !trimmed.is_empty() {
                    trimmed.to_string()
                } else if !digits.is_empty() {
                    "0".to_string()
                } else {
                    c.trim().to_lowercase()
                }
            }
            _ => slugify(&self.title, 40),
        };
        format!("{base}:{bucket}:{cls}")
    }

    pub fn loc(&self) -> String {
        match self.line {
            Some(l) => format!("{}:{}", self.file, l),
            None => self.file.clone(),
        }
    }

    fn has_role(&self, role: &str) -> bool {
        self.taint_path.iter().any(|s| s.role.eq_ignore_ascii_case(role))
    }

    /// The finder traced an untrusted source through to the sink unbroken — the
    /// taint is grounded by a resolved path, not merely asserted. Exposure-class
    /// findings (hardcoded secrets, missing TLS) are grounded with no path.
    pub fn taint_grounded(&self) -> bool {
        match self.taint_status.as_deref() {
            Some("reachable") => self.has_role("source") && self.has_role("sink"),
            Some("exposure") => true,
            _ => false,
        }
    }

    /// The finder's OWN trace refutes exploitability (the value is constant, a
    /// sanitizer kills it, or the sink is unreachable). Such a finding should be
    /// dropped: the finder disproved its own report. Recall-safe — never drops a
    /// `reachable`/`exposure`/`unresolved` outcome, nor one with no outcome recorded.
    pub fn taint_self_refuted(&self) -> bool {
        matches!(self.taint_status.as_deref(), Some("constant") | Some("sanitized") | Some("not_reachable"))
    }

    /// One-line arrow summary of the resolved path (reports / dedup display).
    pub fn taint_summary(&self) -> String {
        if self.taint_path.is_empty() {
            return self.taint_status.clone().unwrap_or_default();
        }
        let path = self
            .taint_path
            .iter()
            .map(|s| match s.line {
                Some(l) => format!("{}@{}:{}", s.role, basename(&s.file), l),
                None => format!("{}@{}", s.role, basename(&s.file)),
            })
            .collect::<Vec<_>>()
            .join(" → ");
        match &self.taint_status {
            Some(st) => format!("[{st}] {path}"),
            None => path,
        }
    }

    /// Multi-line rendering of the path for prompts (one step per line).
    pub fn taint_block(&self) -> String {
        if self.taint_path.is_empty() {
            return self
                .taint_status
                .clone()
                .map(|s| format!("outcome: {s} (no step-by-step path recorded)"))
                .unwrap_or_default();
        }
        let mut out = String::new();
        if let Some(st) = &self.taint_status {
            out.push_str(&format!("outcome: {st}\n"));
        }
        for s in &self.taint_path {
            let loc = match s.line {
                Some(l) => format!("{}:{}", s.file, l),
                None => s.file.clone(),
            };
            out.push_str(&format!("  {} | {} | {}\n", s.role, loc, s.note));
        }
        out.trim_end().to_string()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// RoundResult — the on-disk checkpoint
// ──────────────────────────────────────────────────────────────────────────────

fn default_variant() -> String {
    "default".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundResult {
    pub target: String,
    pub label: String,
    pub status: String,
    #[serde(default)]
    pub focus_area: Option<String>,
    #[serde(default = "default_variant")]
    pub variant: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub prompt_shas: BTreeMap<String, String>,
    #[serde(default)]
    pub prompt_sources: BTreeMap<String, String>,
    #[serde(default)]
    pub timings: BTreeMap<String, f64>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl RoundResult {
    pub fn is_terminal(&self) -> bool {
        TERMINAL_STATUSES.contains(&self.status.as_str())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Accumulation (union + dedup across rounds)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccumulatedFinding {
    pub signature: String,
    pub representative: Finding,
    pub corroboration: usize,
    pub rounds: Vec<String>,
    pub max_severity: String,
}

/// Union every round's findings, collapse by signature, count corroboration.
pub fn accumulate(rounds: &[RoundResult]) -> Vec<AccumulatedFinding> {
    let mut order: Vec<String> = Vec::new();
    let mut buckets: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    let mut labels: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for r in rounds {
        for f in &r.findings {
            let sig = f.signature();
            if !buckets.contains_key(&sig) {
                order.push(sig.clone());
            }
            buckets.entry(sig.clone()).or_default().push(f.clone());
            let labs = labels.entry(sig.clone()).or_default();
            if !labs.contains(&r.label) {
                labs.push(r.label.clone());
            }
        }
    }

    let mut out: Vec<AccumulatedFinding> = Vec::new();
    for sig in order {
        let items = &buckets[&sig];
        let representative = items
            .iter()
            .max_by_key(|f| (sev_rank(&f.severity), f.evidence.len() as i32))
            .unwrap()
            .clone();
        let max_severity = items
            .iter()
            .map(|f| f.severity.clone())
            .max_by_key(|s| sev_rank(s))
            .unwrap_or_else(|| "INFO".to_string());
        out.push(AccumulatedFinding {
            signature: sig.clone(),
            representative,
            corroboration: labels[&sig].len(),
            rounds: labels[&sig].clone(),
            max_severity,
        });
    }
    out.sort_by(|a, b| {
        (sev_rank(&b.max_severity), b.corroboration).cmp(&(sev_rank(&a.max_severity), a.corroboration))
    });
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Triage (adversarial verdict + ranking)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Votes {
    pub real: usize,
    pub false_positive: usize,
    pub uncertain: usize,
    pub lenses: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Verdict {
    pub signature: String,
    pub verdict: String, // REAL | FALSE_POSITIVE | UNCERTAIN  (aggregated)
    pub confidence: f64,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub access_level: Option<String>, // unauthenticated_remote | authenticated | local | physical
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub reachability: Option<String>,
    #[serde(default)]
    pub derived_severity: Option<String>,
    #[serde(default)]
    pub votes: Option<Votes>,
}

/// Re-derive severity from access + precondition count instead of trusting the
/// finder's claim (the reference harness's Phase-4 reranking). Unknown access →
/// keep the claimed severity.
pub fn derive_severity(access: Option<&str>, preconditions: usize, claimed: &str) -> String {
    let a = access.unwrap_or("").to_lowercase();
    // level scale: 4=CRITICAL 3=HIGH 2=MEDIUM 1=LOW 0=INFO
    let base: i32 = if a.contains("unauth") || (a.contains("remote") && !a.contains("auth")) {
        3
    } else if a.contains("auth") {
        2
    } else if a.contains("local") {
        1
    } else if a.contains("phys") {
        1
    } else {
        return norm_severity(claimed);
    };
    let adj: i32 = if preconditions == 0 { 1 } else if preconditions >= 3 { -1 } else { 0 };
    match (base + adj).clamp(0, 4) {
        4 => "CRITICAL",
        3 => "HIGH",
        2 => "MEDIUM",
        1 => "LOW",
        _ => "INFO",
    }
    .to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriagedFinding {
    pub accumulated: AccumulatedFinding,
    pub verdict: Verdict,
    pub rank_score: f64,
}

impl TriagedFinding {
    pub fn confirmed(&self) -> bool {
        self.verdict.verdict == "REAL"
    }
}

pub fn rank(acc: &AccumulatedFinding, verdict: &Verdict) -> f64 {
    // Rank by the verifier's derived severity when available, else the claim.
    let sev = verdict.derived_severity.as_deref().unwrap_or(&acc.max_severity);
    let weight = sev_weight(sev);
    let corro_boost = 1.0 + 0.5 * (acc.corroboration as f64 - 1.0);
    weight * verdict.confidence.max(0.0) * corro_boost
}

pub fn triage(acc: &[AccumulatedFinding], verdicts: &BTreeMap<String, Verdict>) -> Vec<TriagedFinding> {
    let mut out: Vec<TriagedFinding> = acc
        .iter()
        .map(|a| {
            let v = verdicts.get(&a.signature).cloned().unwrap_or(Verdict {
                signature: a.signature.clone(),
                verdict: "UNCERTAIN".to_string(),
                confidence: 0.3,
                reasoning: "no verdict".to_string(),
                ..Default::default()
            });
            let rank_score = rank(a, &v);
            TriagedFinding { accumulated: a.clone(), verdict: v, rank_score }
        })
        .collect();
    out.sort_by(|a, b| {
        (b.confirmed(), b.rank_score)
            .partial_cmp(&(a.confirmed(), a.rank_score))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Attack chains
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStep {
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub title: String,
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chain {
    pub title: String,
    #[serde(default)]
    pub premise: String,
    pub steps: Vec<ChainStep>,
    #[serde(default)]
    pub impact: String,
    pub severity: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Threat model (produced by the threat_model stage; consumed by viz + TUI)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    #[serde(default)]
    pub trust: String, // untrusted-input | trusted-core | external | datastore | other
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataFlow {
    pub src: String,
    pub dst: String,
    #[serde(default)]
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(file: &str, line: Option<u32>, cwe: Option<&str>, sev: &str, title: &str) -> Finding {
        Finding {
            title: title.into(),
            severity: sev.into(),
            file: file.into(),
            line,
            cwe: cwe.map(|s| s.into()),
            description: String::new(),
            evidence: String::new(),
            exploit_premise: String::new(),
            focus_area: None,
            round_label: None,
            taint_path: Vec::new(),
            taint_status: None,
        }
    }

    fn round(label: &str, findings: Vec<Finding>) -> RoundResult {
        RoundResult {
            target: "t".into(),
            label: label.into(),
            status: "completed".into(),
            focus_area: None,
            variant: "default".into(),
            model: "m".into(),
            findings,
            prompt_shas: BTreeMap::new(),
            prompt_sources: BTreeMap::new(),
            timings: BTreeMap::new(),
            session_id: None,
            error: None,
        }
    }

    #[test]
    fn cwe_leading_zero_collides() {
        // CWE-089 and CWE-89 at the same location normalize to one signature.
        let a = f("app.py", Some(30), Some("CWE-089"), "HIGH", "sqli");
        let b = f("app.py", Some(30), Some("CWE-89 SQLi"), "CRITICAL", "SQL injection");
        assert_eq!(a.signature(), b.signature());
        assert_eq!(a.signature(), "app.py:30:89");
    }

    #[test]
    fn title_fallback_when_no_cwe() {
        let a = f("src/app.py", Some(10), None, "LOW", "Weird Bug!");
        assert!(a.signature().starts_with("app.py:10:"));
    }

    #[test]
    fn accumulate_dedups_and_counts_corroboration() {
        let r0 = round("r0", vec![f("app.py", Some(30), Some("CWE-89"), "HIGH", "sqli")]);
        let r1 = round(
            "r1",
            vec![
                f("app.py", Some(30), Some("CWE-89"), "CRITICAL", "SQLi"),
                f("app.py", Some(50), Some("CWE-78"), "CRITICAL", "cmd"),
            ],
        );
        let acc = accumulate(&[r0, r1]);
        assert_eq!(acc.len(), 2);
        // sqli: same line in both rounds → merged, escalated to CRITICAL, ranked first.
        assert_eq!(acc[0].corroboration, 2);
        assert_eq!(acc[0].max_severity, "CRITICAL");
    }

    #[test]
    fn derive_severity_from_access_and_preconditions() {
        assert_eq!(derive_severity(Some("unauthenticated_remote"), 0, "LOW"), "CRITICAL");
        assert_eq!(derive_severity(Some("unauthenticated_remote"), 2, "LOW"), "HIGH");
        assert_eq!(derive_severity(Some("local"), 3, "HIGH"), "INFO");
        assert_eq!(derive_severity(None, 0, "MEDIUM"), "MEDIUM"); // unknown access → keep claim
    }

    #[test]
    fn norm_taint_status_canonicalizes() {
        assert_eq!(norm_taint_status("REACHABLE").as_deref(), Some("reachable"));
        assert_eq!(norm_taint_status("not reachable").as_deref(), Some("not_reachable"));
        assert_eq!(norm_taint_status("constant (getTheValue returns \"bar\")").as_deref(), Some("constant"));
        assert_eq!(norm_taint_status("sanitized upstream").as_deref(), Some("sanitized"));
        assert_eq!(norm_taint_status("exposure / N/A").as_deref(), Some("exposure"));
        assert_eq!(norm_taint_status("   ").as_deref(), None);
    }

    #[test]
    fn taint_self_refuted_only_for_disproved_outcomes() {
        let mut g = f("a.py", Some(5), Some("CWE-89"), "HIGH", "sqli");
        assert!(!g.taint_self_refuted()); // no outcome recorded → kept
        for keep in ["reachable", "exposure", "unresolved"] {
            g.taint_status = Some(keep.into());
            assert!(!g.taint_self_refuted(), "{keep} must be kept");
        }
        for drop in ["constant", "sanitized", "not_reachable"] {
            g.taint_status = Some(drop.into());
            assert!(g.taint_self_refuted(), "{drop} must be dropped");
        }
    }

    #[test]
    fn taint_grounded_requires_source_and_sink_or_exposure() {
        let mut g = f("a.py", Some(5), Some("CWE-89"), "HIGH", "sqli");
        g.taint_status = Some("reachable".into());
        assert!(!g.taint_grounded()); // reachable but no resolved steps
        g.taint_path = vec![
            TaintStep { file: "h.py".into(), line: Some(2), role: "source".into(), note: "req param".into() },
            TaintStep { file: "a.py".into(), line: Some(5), role: "sink".into(), note: "execute".into() },
        ];
        assert!(g.taint_grounded());
        assert_eq!(g.taint_summary(), "[reachable] source@h.py:2 → sink@a.py:5");

        let mut e = f("c.py", Some(1), Some("CWE-798"), "HIGH", "hardcoded key");
        e.taint_status = Some("exposure".into());
        assert!(e.taint_grounded()); // exposure is grounded with no path
    }

    #[test]
    fn triage_puts_confirmed_first_then_rank() {
        let r0 = round(
            "r0",
            vec![
                f("a.py", Some(1), Some("CWE-89"), "HIGH", "a"),
                f("b.py", Some(1), Some("CWE-22"), "CRITICAL", "b"),
            ],
        );
        let acc = accumulate(&[r0]);
        let mut v = BTreeMap::new();
        for a in &acc {
            let verdict = if a.representative.title == "a" { "REAL" } else { "FALSE_POSITIVE" };
            v.insert(a.signature.clone(), Verdict { signature: a.signature.clone(), verdict: verdict.into(), confidence: 0.9, ..Default::default() });
        }
        let t = triage(&acc, &v);
        // The confirmed HIGH outranks the rejected CRITICAL.
        assert!(t[0].confirmed());
        assert_eq!(t[0].accumulated.representative.title, "a");
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ThreatModel {
    #[serde(default)]
    pub narrative: String,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub flows: Vec<DataFlow>,
    #[serde(default)]
    pub boundaries: Vec<String>,
    #[serde(default)]
    pub focus_areas: Vec<String>,
}
