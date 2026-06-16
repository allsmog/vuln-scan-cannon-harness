//! Fleet mode — scan many targets, then reason across them. The union of every
//! target's CONFIRMED findings (tagged by service) is handed to a cross-system
//! chain pass to surface attacks that span services — the bug in service A that
//! only matters because it reaches service B.

use crate::ledger::Ledger;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct FleetConfig {
    pub targets: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TaggedFinding {
    pub target: String,
    /// signature namespaced by service, so two services' findings never collide
    pub signature: String,
    pub title: String,
    pub loc: String,
    pub severity: String,
    pub premise: String,
    pub description: String,
}

/// Union of confirmed findings across the fleet, tagged by service.
pub fn aggregate(ledgers: &[(&str, &Ledger)]) -> Vec<TaggedFinding> {
    let mut out = Vec::new();
    for (name, led) in ledgers {
        for f in led.chainable("confirmed") {
            out.push(TaggedFinding {
                target: name.to_string(),
                signature: format!("{}:{}", name, f.signature),
                title: f.title.clone(),
                loc: format!("{}::{}", name, f.loc()),
                severity: f.severity.clone(),
                premise: f.exploit_premise.clone(),
                description: f.description.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{AccumulatedFinding, Finding, TriagedFinding, Verdict};

    fn confirmed_ledger(name: &str, title: &str, file: &str) -> Ledger {
        let rep = Finding {
            title: title.into(),
            severity: "HIGH".into(),
            file: file.into(),
            line: Some(10),
            cwe: Some("CWE-89".into()),
            description: "d".into(),
            evidence: "e".into(),
            exploit_premise: "p".into(),
            focus_area: None,
            round_label: None,
            ..Default::default()
        };
        let sig = rep.signature();
        let t = TriagedFinding {
            accumulated: AccumulatedFinding { signature: sig.clone(), representative: rep, corroboration: 1, rounds: vec![], max_severity: "HIGH".into() },
            verdict: Verdict { signature: sig, verdict: "REAL".into(), confidence: 0.9, ..Default::default() },
            rank_score: 1.0,
        };
        let mut l = Ledger { target: name.into(), findings: vec![], next_id: 1 };
        l.merge(&[t], "rd");
        l
    }

    #[test]
    fn aggregates_confirmed_across_services_tagged() {
        let a = confirmed_ledger("svc-a", "IDOR in orders", "orders.py");
        let b = confirmed_ledger("svc-b", "SQLi in search", "search.py");
        let agg = aggregate(&[("svc-a", &a), ("svc-b", &b)]);
        assert_eq!(agg.len(), 2);
        assert!(agg.iter().any(|t| t.target == "svc-a" && t.signature.starts_with("svc-a:")));
        assert!(agg.iter().any(|t| t.target == "svc-b" && t.loc.starts_with("svc-b::")));
    }

    #[test]
    fn excludes_non_confirmed() {
        let mut a = confirmed_ledger("svc-a", "IDOR", "o.py");
        a.set_status("F-001", "false_positive", None).unwrap();
        assert_eq!(aggregate(&[("svc-a", &a)]).len(), 0);
    }
}
