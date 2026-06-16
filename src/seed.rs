//! Seed existing vulnerability data into the ledger.
//!
//! Parses external scanner output (SARIF, Semgrep JSON, a generic findings
//! array, or CSV) into cannon `Finding`s. They enter the ledger as `new` /
//! unverified, tagged with their origin; `cannon verify` then runs the
//! adversarial verifier over them — the reference harness's "feed it your
//! existing backlog first, have it disprove what it can" workflow.

use crate::artifacts::{norm_severity, Finding};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::Path;

pub struct Seeded {
    pub findings: Vec<Finding>,
    pub source: String,
}

pub fn parse_file(path: &Path, format: &str) -> Result<Seeded> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let fmt = if format != "auto" { format.to_string() } else { detect(&text) };
    match fmt.as_str() {
        "sarif" => parse_sarif(&text),
        "semgrep" => parse_semgrep(&text),
        "json" => parse_generic_json(&text),
        "csv" => parse_csv(&text),
        other => bail!("unknown --format '{other}' (use sarif|semgrep|json|csv|auto)"),
    }
}

fn detect(text: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        let is_sarif = v.get("runs").is_some()
            && (v.get("version").is_some()
                || v.get("$schema").and_then(|s| s.as_str()).map(|s| s.contains("sarif")).unwrap_or(false));
        if is_sarif {
            return "sarif".into();
        }
        let is_semgrep = v
            .get("results")
            .and_then(|r| r.as_array())
            .map(|a| a.first().map(|x| x.get("check_id").is_some()).unwrap_or(false))
            .unwrap_or(false);
        if is_semgrep {
            return "semgrep".into();
        }
        return "json".into();
    }
    "csv".into()
}

fn extract_cwe(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?i)CWE[-_ ]?(\d+)").ok()?;
    re.captures(text).map(|c| {
        let n = c[1].trim_start_matches('0');
        format!("CWE-{}", if n.is_empty() { "0" } else { n })
    })
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).trim().chars().take(160).collect()
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64().map(|n| n as u32).or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

// ──────────────────────────────────────────────────────────────── SARIF

fn sarif_severity(level: &str, result: &Value, rule: Option<&Value>) -> String {
    // Prefer a numeric security-severity (CVSS-like 0–10) from result or rule.
    let sec = result
        .pointer("/properties/security-severity")
        .or_else(|| rule.and_then(|r| r.pointer("/properties/security-severity")))
        .and_then(|v| v.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| v.as_f64()));
    if let Some(s) = sec {
        return if s >= 9.0 { "CRITICAL" } else if s >= 7.0 { "HIGH" } else if s >= 4.0 { "MEDIUM" } else { "LOW" }.into();
    }
    match level {
        "error" => "HIGH",
        "warning" => "MEDIUM",
        "note" | "none" => "LOW",
        _ => "MEDIUM",
    }
    .into()
}

fn parse_sarif(text: &str) -> Result<Seeded> {
    let v: Value = serde_json::from_str(text).context("parsing SARIF JSON")?;
    let mut findings = Vec::new();
    let mut source = "sarif".to_string();
    let empty: Vec<Value> = Vec::new();

    for run in v.get("runs").and_then(|r| r.as_array()).unwrap_or(&empty) {
        let tool_name = run.pointer("/tool/driver/name").and_then(|s| s.as_str()).unwrap_or("sarif");
        source = format!("sarif:{tool_name}");
        // Rule index for CWE/severity enrichment.
        let rules = run.pointer("/tool/driver/rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
        let find_rule = |id: &str| rules.iter().find(|r| r.get("id").and_then(|i| i.as_str()) == Some(id)).cloned();

        for r in run.get("results").and_then(|x| x.as_array()).unwrap_or(&empty) {
            let rule_id = r.get("ruleId").and_then(|s| s.as_str()).unwrap_or("");
            let rule = find_rule(rule_id);
            let msg = r.pointer("/message/text").and_then(|s| s.as_str()).unwrap_or(rule_id);
            let level = r.get("level").and_then(|s| s.as_str()).unwrap_or("warning");
            let loc = r.pointer("/locations/0/physicalLocation");
            let file = loc
                .and_then(|l| l.pointer("/artifactLocation/uri"))
                .and_then(|s| s.as_str())
                .unwrap_or("?")
                .to_string();
            let line = loc.and_then(|l| l.pointer("/region/startLine")).and_then(as_u32);

            let cwe = extract_cwe(rule_id)
                .or_else(|| rule.as_ref().and_then(|r| extract_cwe(&r.to_string())))
                .or_else(|| extract_cwe(msg));

            findings.push(Finding {
                title: first_line(msg),
                severity: sarif_severity(level, r, rule.as_ref()),
                file,
                line,
                cwe,
                description: format!("[{rule_id}] {msg}"),
                evidence: String::new(),
                exploit_premise: String::new(),
                focus_area: None,
                round_label: None,
                ..Default::default()
            });
        }
    }
    Ok(Seeded { findings, source })
}

// ──────────────────────────────────────────────────────────────── Semgrep

fn parse_semgrep(text: &str) -> Result<Seeded> {
    let v: Value = serde_json::from_str(text).context("parsing Semgrep JSON")?;
    let empty: Vec<Value> = Vec::new();
    let mut findings = Vec::new();
    for r in v.get("results").and_then(|x| x.as_array()).unwrap_or(&empty) {
        let check = r.get("check_id").and_then(|s| s.as_str()).unwrap_or("semgrep");
        let msg = r.pointer("/extra/message").and_then(|s| s.as_str()).unwrap_or(check);
        let sev = match r.pointer("/extra/severity").and_then(|s| s.as_str()).unwrap_or("WARNING") {
            "ERROR" => "HIGH",
            "WARNING" => "MEDIUM",
            _ => "LOW",
        };
        let file = r.get("path").and_then(|s| s.as_str()).unwrap_or("?").to_string();
        let line = r.pointer("/start/line").and_then(as_u32);
        let cwe = r
            .pointer("/extra/metadata/cwe")
            .map(|c| c.to_string())
            .and_then(|s| extract_cwe(&s))
            .or_else(|| extract_cwe(check));
        findings.push(Finding {
            title: first_line(msg),
            severity: sev.into(),
            file,
            line,
            cwe,
            description: format!("[{check}] {msg}"),
            evidence: String::new(),
            exploit_premise: String::new(),
            focus_area: None,
            round_label: None,
            ..Default::default()
        });
    }
    Ok(Seeded { findings, source: "semgrep".into() })
}

// ──────────────────────────────────────────────────────────────── Generic JSON

fn pick<'a>(o: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| o.get(*k))
}
fn pick_str(o: &Value, keys: &[&str]) -> Option<String> {
    pick(o, keys).and_then(|v| v.as_str().map(|s| s.to_string()))
}

fn parse_generic_json(text: &str) -> Result<Seeded> {
    let v: Value = serde_json::from_str(text).context("parsing JSON")?;
    let arr = if let Some(a) = v.as_array() {
        a.clone()
    } else if let Some(a) = v.get("findings").and_then(|x| x.as_array()) {
        a.clone()
    } else if let Some(a) = v.get("results").and_then(|x| x.as_array()) {
        a.clone()
    } else {
        bail!("generic JSON: expected an array, or an object with a 'findings'/'results' array");
    };

    let mut findings = Vec::new();
    for o in &arr {
        let title = pick_str(o, &["title", "name", "rule", "check_id", "message", "ruleId"]).unwrap_or_else(|| "untitled".into());
        let file = pick_str(o, &["file", "path", "filename", "location", "uri"]).unwrap_or_else(|| "?".into());
        let line = pick(o, &["line", "start_line", "startLine", "lineNumber"]).and_then(as_u32);
        let severity = norm_severity(&pick_str(o, &["severity", "level", "priority"]).unwrap_or_default());
        let cwe = pick(o, &["cwe", "cwes", "CWE"]).map(|c| c.to_string()).and_then(|s| extract_cwe(&s));
        let description = pick_str(o, &["description", "message", "details", "text"]).unwrap_or_default();
        findings.push(Finding {
            title: first_line(&title),
            severity,
            file,
            line,
            cwe,
            description,
            evidence: pick_str(o, &["evidence", "snippet", "code"]).unwrap_or_default(),
            exploit_premise: String::new(),
            focus_area: None,
            round_label: None,
            ..Default::default()
        });
    }
    Ok(Seeded { findings, source: "json".into() })
}

// ──────────────────────────────────────────────────────────────── CSV

fn parse_csv(text: &str) -> Result<Seeded> {
    let mut lines = text.lines();
    let header = lines.next().context("empty CSV")?;
    let cols: Vec<String> = header.split(',').map(|c| c.trim().to_lowercase()).collect();
    let col = |row: &[String], names: &[&str]| -> Option<String> {
        names.iter().find_map(|n| cols.iter().position(|c| c == n).and_then(|i| row.get(i).cloned()))
    };
    let mut findings = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let row: Vec<String> = line.split(',').map(|c| c.trim().trim_matches('"').to_string()).collect();
        let title = col(&row, &["title", "name", "rule", "message", "finding"]).unwrap_or_else(|| "untitled".into());
        let file = col(&row, &["file", "path", "filename", "location"]).unwrap_or_else(|| "?".into());
        let line_no = col(&row, &["line", "line_number", "lineno"]).and_then(|s| s.parse().ok());
        let severity = norm_severity(&col(&row, &["severity", "level", "priority"]).unwrap_or_default());
        let cwe = col(&row, &["cwe"]).and_then(|s| extract_cwe(&s));
        let description = col(&row, &["description", "details", "notes"]).unwrap_or_default();
        findings.push(Finding {
            title: first_line(&title),
            severity,
            file,
            line: line_no,
            cwe,
            description,
            evidence: String::new(),
            exploit_premise: String::new(),
            focus_area: None,
            round_label: None,
            ..Default::default()
        });
    }
    Ok(Seeded { findings, source: "csv".into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_and_parse_sarif() {
        let s = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":[{"id":"py/sql","properties":{"tags":["external/cwe/cwe-089"],"security-severity":"9.1"}}]}},"results":[{"ruleId":"py/sql","level":"error","message":{"text":"SQLi here"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":30}}}]}]}]}"#;
        assert_eq!(detect(s), "sarif");
        let out = parse_sarif(s).unwrap();
        assert_eq!(out.source, "sarif:CodeQL");
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.file, "app.py");
        assert_eq!(f.line, Some(30));
        assert_eq!(f.severity, "CRITICAL");
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn parse_semgrep_native() {
        let s = r#"{"results":[{"check_id":"py.sqli","path":"x/app.py","start":{"line":12},"extra":{"message":"bad","severity":"ERROR","metadata":{"cwe":["CWE-89: SQL"]}}}]}"#;
        assert_eq!(detect(s), "semgrep");
        let out = parse_semgrep(s).unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, "HIGH");
        assert_eq!(out.findings[0].cwe.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn parse_generic_and_csv() {
        let j = r#"[{"title":"Open redirect","file":"a.py","line":4,"severity":"medium","cwe":"CWE-601"}]"#;
        let out = parse_generic_json(j).unwrap();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, "MEDIUM");
        let csv = "file,line,severity,title\napp.py,9,high,Path traversal";
        let out2 = parse_csv(csv).unwrap();
        assert_eq!(out2.findings.len(), 1);
        assert_eq!(out2.findings[0].file, "app.py");
        assert_eq!(out2.findings[0].line, Some(9));
        assert_eq!(out2.findings[0].severity, "HIGH");
    }
}
