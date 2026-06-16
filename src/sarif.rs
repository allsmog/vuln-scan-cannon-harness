//! SARIF 2.1.0 output — so cannon's findings flow into GitHub code scanning and
//! any SARIF-aware viewer. (cannon also *ingests* SARIF; see seed.rs.)

use crate::artifacts::{norm_severity, slugify};
use serde_json::{json, Value};

pub struct SarifRow {
    pub rule_id: String,
    pub severity: String,
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
}

fn level(sev: &str) -> &'static str {
    match norm_severity(sev).as_str() {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

fn security_severity(sev: &str) -> &'static str {
    match norm_severity(sev).as_str() {
        "CRITICAL" => "9.5",
        "HIGH" => "8.0",
        "MEDIUM" => "5.0",
        "LOW" => "3.0",
        _ => "1.0",
    }
}

pub fn build_sarif(tool: &str, rows: &[SarifRow]) -> Value {
    // Unique rules.
    let mut seen = std::collections::BTreeMap::new();
    for r in rows {
        seen.entry(r.rule_id.clone()).or_insert_with(|| security_severity(&r.severity));
    }
    let rules: Vec<Value> = seen
        .iter()
        .map(|(id, sec)| json!({ "id": id, "properties": { "security-severity": sec } }))
        .collect();

    let results: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut region = json!({});
            if let Some(l) = r.line {
                region = json!({ "startLine": l });
            }
            json!({
                "ruleId": r.rule_id,
                "level": level(&r.severity),
                "message": { "text": r.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": r.file },
                        "region": region
                    }
                }]
            })
        })
        .collect();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": { "name": tool, "informationUri": "https://github.com/", "rules": rules } },
            "results": results
        }]
    })
}

pub fn rule_id(cwe: Option<&str>, title: &str) -> String {
    match cwe {
        Some(c) if !c.trim().is_empty() => {
            let digits: String = c.chars().filter(|d| d.is_ascii_digit()).collect();
            let digits = digits.trim_start_matches('0');
            if digits.is_empty() { format!("cannon/{}", slugify(title, 40)) } else { format!("CWE-{digits}") }
        }
        _ => format!("cannon/{}", slugify(title, 40)),
    }
}
