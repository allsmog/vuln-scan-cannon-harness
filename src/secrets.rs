//! Deterministic, LLM-free secrets detector — the second detector behind the
//! registry (proves the platform is real; runs free and fast). Pattern rules +
//! a Shannon-entropy heuristic over assignment values.

use crate::artifacts::Finding;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;

struct Rule {
    name: &'static str,
    re: Regex,
    severity: &'static str,
    cwe: &'static str,
}

fn rules() -> &'static Vec<Rule> {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |re: &str| Regex::new(re).unwrap();
        vec![
            Rule { name: "AWS access key id", re: r(r"AKIA[0-9A-Z]{16}"), severity: "HIGH", cwe: "CWE-798" },
            Rule { name: "private key block", re: r(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), severity: "CRITICAL", cwe: "CWE-798" },
            Rule { name: "Stripe-style live key", re: r(r"sk_live_[0-9a-zA-Z]{16,}"), severity: "HIGH", cwe: "CWE-798" },
            Rule { name: "GitHub token", re: r(r"gh[pousr]_[0-9A-Za-z]{30,}"), severity: "HIGH", cwe: "CWE-798" },
            Rule { name: "Slack token", re: r(r"xox[baprs]-[0-9A-Za-z-]{10,}"), severity: "HIGH", cwe: "CWE-798" },
            Rule { name: "Google API key", re: r(r"AIza[0-9A-Za-z_\-]{35}"), severity: "HIGH", cwe: "CWE-798" },
            Rule {
                name: "hardcoded credential",
                re: r("(?i)(api[_-]?key|secret[_-]?key|secret|token|passwd|password|access[_-]?key)\\s*[:=]\\s*['\"][^'\"]{12,}['\"]"),
                severity: "MEDIUM",
                cwe: "CWE-798",
            },
        ]
    })
}

/// Shannon entropy (bits/char) of a string.
fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn redact(line: &str) -> String {
    let t = line.trim();
    let t: String = t.chars().take(120).collect();
    // Mask the middle of any long token to avoid copying the live secret around.
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    let re = QUOTED.get_or_init(|| Regex::new(r#"([A-Za-z0-9_\-+/]{12,})"#).unwrap());
    re.replace_all(&t, |c: &regex::Captures| {
        let s = &c[1];
        if s.len() <= 10 {
            s.to_string()
        } else {
            format!("{}…{}", &s[..4], &s[s.len() - 2..])
        }
    })
    .to_string()
}

/// Candidate high-entropy quoted value (entropy heuristic, separate from rules).
fn entropy_hit(line: &str) -> bool {
    static VALRE: OnceLock<Regex> = OnceLock::new();
    let re = VALRE.get_or_init(|| Regex::new(r#"['"]([A-Za-z0-9+/=_\-]{24,})['"]"#).unwrap());
    re.captures_iter(line).any(|c| {
        let v = &c[1];
        // Avoid obvious non-secrets: URLs, all-same-class short words handled by length.
        entropy(v) >= 4.0 && v.chars().any(|ch| ch.is_ascii_digit()) && v.chars().any(|ch| ch.is_ascii_alphabetic())
    })
}

pub fn scan_text(rel_path: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.len() > 4000 {
            continue; // minified/data line
        }
        let mut matched = false;
        for rule in rules() {
            if rule.re.is_match(line) {
                out.push(Finding {
                    title: format!("Hardcoded secret: {}", rule.name),
                    severity: rule.severity.to_string(),
                    file: rel_path.to_string(),
                    line: Some((i + 1) as u32),
                    cwe: Some(rule.cwe.to_string()),
                    description: format!(
                        "A {} appears to be hardcoded in source. Anyone with read access to the repository, a CI artifact, or a container layer obtains the secret.",
                        rule.name
                    ),
                    evidence: redact(line),
                    exploit_premise: "Read access to the source (repo, CI log, image layer). No execution required.".to_string(),
                    focus_area: None,
                    round_label: None,
                    taint_status: Some("exposure".into()),
                    ..Default::default()
                });
                matched = true;
                break;
            }
        }
        if !matched && entropy_hit(line) {
            out.push(Finding {
                title: "Possible hardcoded secret (high-entropy string)".to_string(),
                severity: "LOW".to_string(),
                file: rel_path.to_string(),
                line: Some((i + 1) as u32),
                cwe: Some("CWE-798".to_string()),
                description: "A high-entropy string literal that may be a hardcoded secret. Lower confidence — verify whether it is sensitive.".to_string(),
                evidence: redact(line),
                exploit_premise: "Read access to the source if the value is sensitive.".to_string(),
                focus_area: None,
                round_label: None,
                taint_status: Some("exposure".into()),
                ..Default::default()
            });
        }
    }
    out
}

const SKIP_DIRS: [&str; 6] = [".git", "node_modules", "target", ".venv", "__pycache__", "dist"];
const SKIP_EXT: [&str; 14] = [
    "png", "jpg", "jpeg", "gif", "pdf", "zip", "gz", "tar", "wasm", "lock", "min.js", "map", "ico", "svg",
];

pub fn scan_dir(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            !e.file_name().to_str().map(|n| SKIP_DIRS.contains(&n)).unwrap_or(false)
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        if SKIP_EXT.contains(&ext.as_str()) {
            continue;
        }
        if path.metadata().map(|m| m.len() > 2_000_000).unwrap_or(false) {
            continue;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rel = path.strip_prefix(root).unwrap_or(path).display().to_string();
        out.extend(scan_text(&rel, &content));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_stripe_live_key() {
        // Assembled at runtime so the contiguous "sk_live_<key>" literal never
        // appears in source — the rule is still exercised against the full token,
        // but GitHub push-protection has nothing to flag in a public repo.
        let key = format!("sk_live_{}", "9d8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b");
        let f = scan_text("app.py", &format!("SECRET_KEY = \"{key}\""));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe.as_deref(), Some("CWE-798"));
        assert_eq!(f[0].line, Some(1));
        assert!(!f[0].evidence.contains("9d8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b")); // redacted
    }

    #[test]
    fn detects_aws_and_private_key() {
        assert_eq!(scan_text("a", "key = AKIAIOSFODNN7EXAMPLE").len(), 1);
        assert_eq!(scan_text("b", "-----BEGIN RSA PRIVATE KEY-----").len(), 1);
        assert_eq!(scan_text("b", "-----BEGIN RSA PRIVATE KEY-----")[0].severity, "CRITICAL");
    }

    #[test]
    fn ignores_normal_code() {
        let clean = "def add(a, b):\n    return a + b  # simple\nx = 'hello world this is fine'\n";
        assert_eq!(scan_text("ok.py", clean).len(), 0);
    }

    #[test]
    fn entropy_heuristic_flags_long_random_token() {
        // a long base64-ish token assigned to a non-secret-named var
        let f = scan_text("x", "blob = 'aGVsbG8x827Yz92Kd0planQ4ssMz19xQ'");
        assert!(f.iter().any(|x| x.severity == "LOW"));
    }

    #[test]
    fn entropy_value_is_higher_for_random() {
        assert!(entropy("aaaaaaaa") < 1.0);
        assert!(entropy("aB3x9Kf2QzL7") > 3.0);
    }
}
