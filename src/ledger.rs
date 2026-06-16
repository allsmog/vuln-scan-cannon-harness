//! The persistent, per-target findings ledger.
//!
//! Canonical state lives in `targets/<t>/.cannon/ledger.json`; the human-facing
//! `targets/<t>/VULN_FINDINGS.md` is rendered from it and its `status`/`note`
//! tokens are round-tripped back. Runs merge in by signature; **human triage
//! decisions are sticky** (`triaged_by = "human"` is never overwritten by a
//! re-merge). New findings are seeded from the adversarial verifier's verdict
//! (`triaged_by = "auto"`) so `fire --chain` works out of the box, while the
//! human keeps final say.

use crate::artifacts::{norm_severity, sev_rank, AccumulatedFinding, Finding, TaintStep, TriagedFinding, Verdict};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const STATUSES: [&str; 6] = ["new", "confirmed", "false_positive", "accepted", "fixed", "duplicate"];

pub fn valid_status(s: &str) -> bool {
    STATUSES.contains(&s)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerFinding {
    pub id: String,
    pub signature: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub cwe: Option<String>,
    pub file: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub exploit_premise: String,
    #[serde(default)]
    pub recommendation: String,
    pub status: String,
    #[serde(default)]
    pub triaged_by: String, // "auto" | "human"
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub corroboration: usize,
    #[serde(default)]
    pub rounds: Vec<String>,
    #[serde(default)]
    pub verifier_verdict: Option<String>,
    #[serde(default)]
    pub verifier_confidence: Option<f64>,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub provenance: Vec<String>,
    /// Where this finding came from: "cannon", "semgrep", "sarif:CodeQL", …
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub access_level: Option<String>,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub reachability: Option<String>,
    /// the finder's original severity, kept when the verifier derived a new one
    #[serde(default)]
    pub claimed_severity: Option<String>,
    /// Cross-file taint path the finder resolved (agentic taint resolution).
    #[serde(default)]
    pub taint_path: Vec<TaintStep>,
    #[serde(default)]
    pub taint_status: Option<String>,
}

impl LedgerFinding {
    pub fn loc(&self) -> String {
        match self.line {
            Some(l) => format!("{}:{}", self.file, l),
            None => self.file.clone(),
        }
    }

    /// Reconstruct a Finding (for handing to the verifier prompt).
    pub fn as_finding(&self) -> Finding {
        Finding {
            title: self.title.clone(),
            severity: self.severity.clone(),
            file: self.file.clone(),
            line: self.line,
            cwe: self.cwe.clone(),
            description: self.description.clone(),
            evidence: self.evidence.clone(),
            exploit_premise: self.exploit_premise.clone(),
            focus_area: None,
            round_label: None,
            taint_path: self.taint_path.clone(),
            taint_status: self.taint_status.clone(),
        }
    }

    pub fn as_accumulated(&self) -> AccumulatedFinding {
        AccumulatedFinding {
            signature: self.signature.clone(),
            representative: self.as_finding(),
            corroboration: self.corroboration.max(1),
            rounds: self.rounds.clone(),
            max_severity: self.severity.clone(),
        }
    }

    /// Fold a verifier verdict in: record verdict/confidence/access/preconditions/
    /// reachability, and let a derived severity replace the claim (keeping the
    /// original as `claimed_severity`).
    pub fn absorb_verdict(&mut self, v: &Verdict) {
        self.verifier_verdict = Some(v.verdict.clone());
        self.verifier_confidence = Some(v.confidence);
        self.access_level = v.access_level.clone();
        self.preconditions = v.preconditions.clone();
        self.reachability = v.reachability.clone();
        if let Some(d) = &v.derived_severity {
            if self.claimed_severity.is_none() {
                self.claimed_severity = Some(self.severity.clone());
            }
            self.severity = d.clone();
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub target: String,
    #[serde(default)]
    pub findings: Vec<LedgerFinding>,
    #[serde(default)]
    pub next_id: usize,
}

fn status_from_verdict(verdict: &str) -> &'static str {
    match verdict {
        "REAL" => "confirmed",
        "FALSE_POSITIVE" => "false_positive",
        _ => "new",
    }
}

fn now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()
}

impl Ledger {
    pub fn json_path(target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(".cannon").join("ledger.json")
    }
    pub fn md_path(target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("VULN_FINDINGS.md")
    }

    pub fn load(target_dir: &Path, target_name: &str) -> Ledger {
        let p = Self::json_path(target_dir);
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(l) = serde_json::from_str::<Ledger>(&s) {
                return l;
            }
        }
        Ledger { target: target_name.to_string(), findings: Vec::new(), next_id: 1 }
    }

    pub fn save(&self, target_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(target_dir.join(".cannon"))?;
        std::fs::write(Self::json_path(target_dir), serde_json::to_string_pretty(self)?)?;
        std::fs::write(Self::md_path(target_dir), self.render_md())?;
        // SARIF of everything not killed — for GitHub code scanning / CI.
        let rows: Vec<crate::sarif::SarifRow> = self
            .findings
            .iter()
            .filter(|f| !["false_positive", "duplicate"].contains(&f.status.as_str()))
            .map(|f| crate::sarif::SarifRow {
                rule_id: crate::sarif::rule_id(f.cwe.as_deref(), &f.title),
                severity: f.severity.clone(),
                file: f.file.clone(),
                line: f.line,
                message: format!("[{}] {}", f.id, f.title),
            })
            .collect();
        std::fs::write(
            target_dir.join("findings.sarif"),
            serde_json::to_string_pretty(&crate::sarif::build_sarif("cannon", &rows))?,
        )?;
        Ok(())
    }

    pub fn by_id_mut(&mut self, id: &str) -> Option<&mut LedgerFinding> {
        self.findings.iter_mut().find(|f| f.id.eq_ignore_ascii_case(id))
    }

    /// Findings selected for chaining, by scope.
    pub fn chainable(&self, scope: &str) -> Vec<&LedgerFinding> {
        self.findings
            .iter()
            .filter(|f| match scope {
                "accepted" => f.status == "confirmed" || f.status == "accepted",
                "triaged" => !["new", "false_positive", "duplicate"].contains(&f.status.as_str()),
                _ => f.status == "confirmed", // default
            })
            .collect()
    }

    /// Merge one run's triaged findings into the ledger (sticky human decisions).
    pub fn merge(&mut self, triaged: &[TriagedFinding], results_dir: &str) -> (usize, usize) {
        let now = now_str();
        let mut added = 0;
        let mut updated = 0;
        for t in triaged {
            let acc = &t.accumulated;
            let f = &acc.representative;
            let verdict = t.verdict.verdict.clone();

            if let Some(existing) = self.findings.iter_mut().find(|x| x.signature == acc.signature) {
                existing.corroboration = acc.corroboration;
                for r in &acc.rounds {
                    if !existing.rounds.contains(r) {
                        existing.rounds.push(r.clone());
                    }
                }
                if !f.evidence.is_empty() {
                    existing.evidence = f.evidence.clone();
                }
                if !f.taint_path.is_empty() || f.taint_status.is_some() {
                    existing.taint_path = f.taint_path.clone();
                    existing.taint_status = f.taint_status.clone();
                }
                existing.severity = acc.max_severity.clone();
                existing.absorb_verdict(&t.verdict);
                existing.last_seen = now.clone();
                if !existing.provenance.contains(&results_dir.to_string()) {
                    existing.provenance.push(results_dir.to_string());
                }
                // Sticky: only an auto decision is re-derived from the verifier.
                if existing.triaged_by != "human" {
                    existing.status = status_from_verdict(&verdict).to_string();
                    existing.triaged_by = "auto".to_string();
                }
                updated += 1;
            } else {
                let id = format!("F-{:03}", self.next_id);
                self.next_id += 1;
                let mut nf = LedgerFinding {
                    id,
                    signature: acc.signature.clone(),
                    title: f.title.clone(),
                    severity: acc.max_severity.clone(),
                    cwe: f.cwe.clone(),
                    file: f.file.clone(),
                    line: f.line,
                    category: f.cwe.clone().unwrap_or_default(),
                    description: f.description.clone(),
                    evidence: f.evidence.clone(),
                    exploit_premise: f.exploit_premise.clone(),
                    recommendation: String::new(),
                    status: status_from_verdict(&verdict).to_string(),
                    triaged_by: "auto".to_string(),
                    note: String::new(),
                    corroboration: acc.corroboration,
                    rounds: acc.rounds.clone(),
                    verifier_verdict: None,
                    verifier_confidence: None,
                    first_seen: now.clone(),
                    last_seen: now.clone(),
                    provenance: vec![results_dir.to_string()],
                    sources: vec!["cannon".to_string()],
                    access_level: None,
                    preconditions: Vec::new(),
                    reachability: None,
                    claimed_severity: None,
                    taint_path: f.taint_path.clone(),
                    taint_status: f.taint_status.clone(),
                };
                nf.absorb_verdict(&t.verdict);
                self.findings.push(nf);
                added += 1;
            }
        }
        (added, updated)
    }

    /// Merge externally-seeded findings (from another scanner / backlog). These
    /// have no cannon verdict, so they enter as `new` / unverified, tagged with
    /// their origin. Existing findings just gain the new source. Returns
    /// (added, updated, signatures_of_new) so callers can verify only the new ones.
    pub fn merge_seeds(&mut self, findings: &[Finding], source: &str) -> (usize, usize, Vec<String>) {
        let now = now_str();
        let (mut added, mut updated) = (0, 0);
        let mut new_sigs = Vec::new();
        for f in findings {
            let sig = f.signature();
            if let Some(ex) = self.findings.iter_mut().find(|x| x.signature == sig) {
                if !ex.sources.iter().any(|s| s == source) {
                    ex.sources.push(source.to_string());
                }
                if ex.evidence.is_empty() && !f.evidence.is_empty() {
                    ex.evidence = f.evidence.clone();
                }
                if ex.description.is_empty() && !f.description.is_empty() {
                    ex.description = f.description.clone();
                }
                ex.last_seen = now.clone();
                updated += 1;
            } else {
                let id = format!("F-{:03}", self.next_id);
                self.next_id += 1;
                self.findings.push(LedgerFinding {
                    id,
                    signature: sig.clone(),
                    title: f.title.clone(),
                    severity: norm_severity(&f.severity),
                    cwe: f.cwe.clone(),
                    file: f.file.clone(),
                    line: f.line,
                    category: f.cwe.clone().unwrap_or_default(),
                    description: f.description.clone(),
                    evidence: f.evidence.clone(),
                    exploit_premise: f.exploit_premise.clone(),
                    recommendation: String::new(),
                    status: "new".to_string(),
                    triaged_by: "imported".to_string(),
                    note: String::new(),
                    corroboration: 1,
                    rounds: Vec::new(),
                    verifier_verdict: None,
                    verifier_confidence: None,
                    first_seen: now.clone(),
                    last_seen: now.clone(),
                    provenance: Vec::new(),
                    sources: vec![source.to_string()],
                    access_level: None,
                    preconditions: Vec::new(),
                    reachability: None,
                    claimed_severity: None,
                    taint_path: f.taint_path.clone(),
                    taint_status: f.taint_status.clone(),
                });
                new_sigs.push(sig);
                added += 1;
            }
        }
        (added, updated, new_sigs)
    }

    /// Apply adversarial verdicts to ledger findings (e.g. after verifying
    /// seeded data). Sticky: a human-set status is never overwritten. Returns
    /// (confirmed, false_positive) counts among those touched.
    pub fn apply_verdicts(&mut self, verdicts: &BTreeMap<String, Verdict>) -> (usize, usize) {
        let (mut conf, mut fp) = (0, 0);
        for f in &mut self.findings {
            if let Some(v) = verdicts.get(&f.signature) {
                f.absorb_verdict(v);
                if f.triaged_by != "human" {
                    f.status = status_from_verdict(&v.verdict).to_string();
                    f.triaged_by = "auto".to_string();
                }
                match v.verdict.as_str() {
                    "REAL" => conf += 1,
                    "FALSE_POSITIVE" => fp += 1,
                    _ => {}
                }
            }
        }
        (conf, fp)
    }


    fn sorted(&self) -> Vec<&LedgerFinding> {
        let mut v: Vec<&LedgerFinding> = self.findings.iter().collect();
        v.sort_by(|a, b| {
            sev_rank(&b.severity)
                .cmp(&sev_rank(&a.severity))
                .then(a.id.cmp(&b.id))
        });
        v
    }

    pub fn render_md(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# VULN_FINDINGS — {}\n\n", self.target));
        out.push_str(
            "Managed findings ledger. Edit a finding's `<!-- cannon:status=… -->` token \
(one of: new, confirmed, false_positive, accepted, fixed, duplicate) and/or its \
`note:` line, then run `cannon findings sync ` to save. CLI: \
`cannon findings set  F-NNN --status confirmed`. The TUI (`cannon tui `) edits \
the same store.\n\n",
        );
        // Summary table
        out.push_str("| id | sev | status | finding | location |\n|---|---|---|---|---|\n");
        for f in self.sorted() {
            out.push_str(&format!(
                "| {} | {} | {} | {} | `{}` |\n",
                f.id, f.severity, f.status, f.title.replace('|', "/"), f.loc()
            ));
        }
        out.push('\n');
        for f in self.sorted() {
            out.push_str(&format!("### {} · {} · {}\n", f.id, f.severity, f.title));
            out.push_str(&format!("<!-- cannon:status={} -->\n", f.status));
            let cwe = f.cwe.clone().unwrap_or_else(|| "unspecified".into());
            let vv = match (&f.verifier_verdict, f.verifier_confidence) {
                (Some(v), Some(c)) => format!("{v} ({c:.2})"),
                _ => "—".into(),
            };
            let src = if f.sources.is_empty() { "cannon".to_string() } else { f.sources.join(",") };
            out.push_str(&format!(
                "- file: `{}` · cwe: {} · ×{} rounds · verifier: {} · triaged_by: {} · src: {}\n",
                f.loc(), cwe, f.corroboration, vv, f.triaged_by, src
            ));
            if let Some(cl) = &f.claimed_severity {
                if cl != &f.severity {
                    out.push_str(&format!("- severity: {} (verifier-derived; finder claimed {})\n", f.severity, cl));
                }
            }
            if let Some(a) = &f.access_level {
                let pc = if f.preconditions.is_empty() { "none".to_string() } else { f.preconditions.join("; ") };
                out.push_str(&format!("- access: {a} · preconditions: {pc}\n"));
            }
            out.push_str(&format!("- note: {}\n\n", f.note));
            if !f.description.is_empty() {
                out.push_str(&format!("{}\n\n", f.description));
            }
            if !f.exploit_premise.is_empty() {
                out.push_str(&format!("**Exploit premise:** {}\n\n", f.exploit_premise));
            }
            if !f.evidence.is_empty() {
                let ev = f.evidence.trim();
                let ev: String = ev.chars().take(1500).collect();
                out.push_str(&format!("**Evidence:**\n\n```\n{}\n```\n\n", ev));
            }
            out.push_str("---\n\n");
        }
        out
    }

    /// Reconcile hand-edited status/note tokens from VULN_FINDINGS.md back into
    /// the ledger. Returns number of findings changed.
    pub fn sync_from_md(&mut self, target_dir: &Path) -> usize {
        let md = match std::fs::read_to_string(Self::md_path(target_dir)) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let id_re = regex::Regex::new(r"^###\s+(F-\d+)\b").unwrap();
        let status_re = regex::Regex::new(r"<!--\s*cannon:status=(\w+)\s*-->").unwrap();
        let note_re = regex::Regex::new(r"^-\s*note:\s*(.*)$").unwrap();

        // Collect parsed (id -> (status, note)).
        let mut parsed: Vec<(String, Option<String>, Option<String>)> = Vec::new();
        let mut cur: Option<usize> = None;
        for line in md.lines() {
            if let Some(c) = id_re.captures(line) {
                parsed.push((c[1].to_string(), None, None));
                cur = Some(parsed.len() - 1);
            } else if let Some(c) = status_re.captures(line) {
                if let Some(i) = cur {
                    parsed[i].1 = Some(c[1].to_string());
                }
            } else if let Some(c) = note_re.captures(line) {
                if let Some(i) = cur {
                    let n = c[1].trim().to_string();
                    parsed[i].2 = Some(n);
                }
            }
        }

        let mut changed = 0;
        for (id, status, note) in parsed {
            if let Some(f) = self.by_id_mut(&id) {
                let mut touched = false;
                if let Some(s) = status {
                    if valid_status(&s) && s != f.status {
                        f.status = s;
                        f.triaged_by = "human".to_string();
                        touched = true;
                    }
                }
                if let Some(n) = note {
                    if n != f.note {
                        f.note = n;
                        touched = true;
                    }
                }
                if touched {
                    changed += 1;
                }
            }
        }
        changed
    }

    /// CLI/TUI status set (marks the decision human-owned).
    pub fn set_status(&mut self, id: &str, status: &str, note: Option<String>) -> Result<()> {
        if !valid_status(status) {
            anyhow::bail!("invalid status '{}'; one of: {}", status, STATUSES.join(", "));
        }
        let f = self
            .by_id_mut(id)
            .ok_or_else(|| anyhow::anyhow!("no finding '{}'", id))?;
        f.status = status.to_string();
        f.triaged_by = "human".to_string();
        if let Some(n) = note {
            f.note = n;
        }
        Ok(())
    }

    /// Set just the note (does not change triage ownership).
    pub fn set_note(&mut self, id: &str, note: String) {
        if let Some(f) = self.by_id_mut(id) {
            f.note = note;
        }
    }

    /// Per-repo calibration: a block describing previously-rejected findings, fed
    /// to the verifier so it learns this repo's false-positive patterns. Empty
    /// until the ledger has some false_positive history.
    pub fn calibration_block(&self) -> String {
        let fps: Vec<&LedgerFinding> = self.findings.iter().filter(|f| f.status == "false_positive").collect();
        if fps.is_empty() {
            return String::new();
        }
        let mut lines = vec![
            "Known FALSE-POSITIVE patterns previously reviewed and rejected in THIS repository. \
Be extra skeptical of findings that resemble these — but still judge the ACTUAL code in front of \
you, and never auto-reject solely because of a resemblance:"
                .to_string(),
        ];
        for f in fps.iter().take(12) {
            let reason = f
                .reachability
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| if f.note.is_empty() { None } else { Some(f.note.clone()) })
                .unwrap_or_else(|| "previously rejected".to_string());
            let reason: String = reason.chars().take(160).collect();
            lines.push(format!("- [{}] {} @ {} — rejected: {}", f.cwe.clone().unwrap_or_default(), f.title, f.loc(), reason));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{AccumulatedFinding, Finding, TriagedFinding, Verdict};

    fn finding() -> Finding {
        Finding {
            title: "SQLi".into(),
            severity: "HIGH".into(),
            file: "app.py".into(),
            line: Some(30),
            cwe: Some("CWE-89".into()),
            description: "d".into(),
            evidence: "e".into(),
            exploit_premise: String::new(),
            focus_area: None,
            round_label: None,
            ..Default::default()
        }
    }

    fn triaged(verdict: &str) -> TriagedFinding {
        let rep = finding();
        let sig = rep.signature();
        TriagedFinding {
            accumulated: AccumulatedFinding {
                signature: sig.clone(),
                representative: rep,
                corroboration: 1,
                rounds: vec!["r0".into()],
                max_severity: "HIGH".into(),
            },
            verdict: Verdict { signature: sig, verdict: verdict.into(), confidence: 0.9, ..Default::default() },
            rank_score: 1.0,
        }
    }

    #[test]
    fn human_decisions_are_sticky_across_remerge() {
        let mut l = Ledger { target: "t".into(), findings: vec![], next_id: 1 };
        l.merge(&[triaged("REAL")], "rd1");
        assert_eq!(l.findings[0].status, "confirmed");
        l.set_status("F-001", "false_positive", None).unwrap();
        l.merge(&[triaged("REAL")], "rd2"); // would re-confirm if not sticky
        assert_eq!(l.findings[0].status, "false_positive");
        assert_eq!(l.findings[0].triaged_by, "human");
    }

    #[test]
    fn seed_dedups_against_existing_and_adds_new() {
        let mut l = Ledger { target: "t".into(), findings: vec![], next_id: 1 };
        l.merge(&[triaged("REAL")], "rd");
        let (a, u, _) = l.merge_seeds(&[finding()], "sarif:Demo"); // same coords → dedup
        assert_eq!((a, u), (0, 1));
        assert!(l.findings[0].sources.contains(&"sarif:Demo".to_string()));
        let other = Finding { file: "other.py".into(), line: Some(7), cwe: Some("CWE-22".into()), ..finding() };
        let (a2, _, new_sigs) = l.merge_seeds(&[other], "json");
        assert_eq!(a2, 1);
        assert_eq!(new_sigs.len(), 1);
        let nf = l.findings.iter().find(|x| x.file == "other.py").unwrap();
        assert_eq!(nf.status, "new");
        assert_eq!(nf.triaged_by, "imported");
    }

    #[test]
    fn md_status_token_round_trips() {
        let dir = std::env::temp_dir().join("cannon_ledger_rt_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut l = Ledger { target: "t".into(), findings: vec![], next_id: 1 };
        l.merge(&[triaged("REAL")], "rd");
        l.save(&dir).unwrap();
        let md = std::fs::read_to_string(Ledger::md_path(&dir)).unwrap();
        std::fs::write(Ledger::md_path(&dir), md.replace("cannon:status=confirmed", "cannon:status=accepted")).unwrap();
        assert_eq!(l.sync_from_md(&dir), 1);
        assert_eq!(l.findings[0].status, "accepted");
        assert_eq!(l.findings[0].triaged_by, "human");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn calibration_block_reflects_false_positives() {
        let mut l = Ledger { target: "t".into(), findings: vec![], next_id: 1 };
        assert!(l.calibration_block().is_empty());
        l.merge(&[triaged("REAL")], "rd");
        l.set_status("F-001", "false_positive", Some("not reachable".into())).unwrap();
        let block = l.calibration_block();
        assert!(block.contains("SQLi"));
        assert!(block.contains("not reachable"));
        assert!(block.to_uppercase().contains("FALSE-POSITIVE"));
    }
}
