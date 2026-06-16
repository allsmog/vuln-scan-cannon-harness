//! Threat-intel (#3) — tailor the salvo to *this* stack's known footguns.
//!
//! Deterministic core: parse the dependency manifests, then map each dependency
//! to its classic vulnerability class via a built-in footgun table → targeted
//! proposals ("hunt prototype pollution in lodash usage"). Optional enhancement:
//! a web-research agent that looks up live CVEs for the detected deps/versions.
//!
//! The parsers + footgun table are pure and unit-tested; only `research` uses an
//! agent.

use crate::agent::{parse_all_tags, run_agent, AgentOpts};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::load_prompt;
use crate::queue::{Proposal, ProposalSpec};
use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Clone, Debug, PartialEq)]
pub struct Dep {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Default)]
pub struct Stack {
    pub deps: Vec<Dep>,
    pub manifests: Vec<String>,
}

// ── manifest parsers (pure) ─────────────────────────────────────────────────

pub fn parse_package_json(text: &str) -> Vec<Dep> {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(obj) = v.get(key).and_then(|o| o.as_object()) {
            for (name, ver) in obj {
                out.push(Dep { name: name.clone(), version: ver.as_str().unwrap_or("").trim_start_matches(['^', '~', '>', '=', ' ']).to_string() });
            }
        }
    }
    out
}

pub fn parse_requirements_txt(text: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let name_end = line.find(['=', '>', '<', '~', '!', ' ', '[', ';']).unwrap_or(line.len());
        let name = line[..name_end].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let version = line[name_end..].trim_start_matches(['=', '>', '<', '~', '!', ' ']).split([' ', ';', ',']).next().unwrap_or("").to_string();
        out.push(Dep { name, version });
    }
    out
}

pub fn parse_cargo_toml(text: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t.contains("dependencies");
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((name, rest)) = t.split_once('=') {
            let name = name.trim().to_string();
            if name.is_empty() {
                continue;
            }
            // version = "1.2" or { version = "1.2", ... }
            let version = rest
                .split("version")
                .nth(if rest.contains("version") { 1 } else { 0 })
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '.')
                .collect::<String>();
            out.push(Dep { name, version });
        }
    }
    out
}

pub fn parse_go_mod(text: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim().trim_start_matches("require ").trim();
        if t.is_empty() || t.starts_with("module ") || t.starts_with("go ") || t == "require (" || t == ")" || t.starts_with("//") {
            continue;
        }
        let mut parts = t.split_whitespace();
        if let Some(name) = parts.next() {
            if name.contains('/') || name.contains('.') {
                out.push(Dep { name: name.to_string(), version: parts.next().unwrap_or("").to_string() });
            }
        }
    }
    out
}

pub fn parse_pom_xml(text: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    for chunk in text.split("<artifactId>").skip(1) {
        if let Some(end) = chunk.find("</artifactId>") {
            out.push(Dep { name: chunk[..end].trim().to_string(), version: String::new() });
        }
    }
    out
}

pub fn detect_stack(source_root: &Path) -> Stack {
    let mut stack = Stack::default();
    for entry in WalkDir::new(source_root).max_depth(3).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
        let name = entry.file_name().to_string_lossy().to_string();
        let text = match std::fs::read_to_string(entry.path()) {
            Ok(t) if t.len() < 500_000 => t,
            _ => continue,
        };
        let parsed = match name.as_str() {
            "package.json" => parse_package_json(&text),
            "requirements.txt" => parse_requirements_txt(&text),
            "Cargo.toml" => parse_cargo_toml(&text),
            "go.mod" => parse_go_mod(&text),
            "pom.xml" => parse_pom_xml(&text),
            _ => continue,
        };
        if !parsed.is_empty() {
            stack.manifests.push(name);
            stack.deps.extend(parsed);
        }
    }
    stack
}

// ── footgun table (pure) ────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Footgun {
    pub needle: &'static str,
    pub class: &'static str,
    pub hint: &'static str,
    pub weight: f64,
}

const FOOTGUNS: [Footgun; 28] = [
    Footgun { needle: "lodash", class: "prototype pollution", hint: "merge/set/defaultsDeep on attacker-controlled keys pollute Object.prototype.", weight: 0.8 },
    Footgun { needle: "jquery", class: "DOM XSS", hint: "$(html) and .html() with untrusted input inject script.", weight: 0.7 },
    Footgun { needle: "express", class: "missing input validation / open redirect", hint: "unvalidated req.params/query/body into responses, redirects, queries.", weight: 0.65 },
    Footgun { needle: "marked", class: "XSS", hint: "rendered markdown with HTML enabled passes through script.", weight: 0.75 },
    Footgun { needle: "markdown-it", class: "XSS", hint: "html:true or unsanitized output injects script.", weight: 0.75 },
    Footgun { needle: "handlebars", class: "template injection / XSS", hint: "triple-stache {{{ }}} and SSTI via compiled templates.", weight: 0.75 },
    Footgun { needle: "jsonwebtoken", class: "JWT algorithm confusion", hint: "alg:none or HS/RS confusion lets tokens be forged.", weight: 0.85 },
    Footgun { needle: "jwt", class: "JWT algorithm confusion", hint: "verify without pinning the algorithm allows forgery.", weight: 0.85 },
    Footgun { needle: "mongoose", class: "NoSQL injection", hint: "operator injection ($where/$gt) via untrusted query objects.", weight: 0.8 },
    Footgun { needle: "sequelize", class: "SQL injection", hint: "raw queries / sequelize.literal with interpolated input.", weight: 0.85 },
    Footgun { needle: "knex", class: "SQL injection", hint: "knex.raw with interpolated user input.", weight: 0.85 },
    Footgun { needle: "axios", class: "SSRF", hint: "requests to attacker-controlled URLs reach internal services.", weight: 0.75 },
    Footgun { needle: "request", class: "SSRF", hint: "outbound requests to user-supplied URLs.", weight: 0.7 },
    Footgun { needle: "multer", class: "unrestricted file upload / path traversal", hint: "filename/destination from the client write outside the upload dir.", weight: 0.8 },
    Footgun { needle: "flask", class: "SSTI / debug RCE", hint: "render_template_string on input; debug=True console.", weight: 0.85 },
    Footgun { needle: "jinja2", class: "server-side template injection", hint: "untrusted templates evaluate arbitrary expressions.", weight: 0.85 },
    Footgun { needle: "django", class: "mass assignment / ORM injection", hint: "ModelForm without fields whitelist; .extra()/.raw() with input.", weight: 0.75 },
    Footgun { needle: "pyyaml", class: "unsafe deserialization", hint: "yaml.load (not safe_load) executes arbitrary Python.", weight: 0.9 },
    Footgun { needle: "yaml", class: "unsafe deserialization", hint: "unsafe YAML load constructs arbitrary objects.", weight: 0.85 },
    Footgun { needle: "pickle", class: "unsafe deserialization", hint: "pickle.loads on untrusted bytes is RCE.", weight: 0.95 },
    Footgun { needle: "lxml", class: "XXE", hint: "external entity resolution on untrusted XML.", weight: 0.8 },
    Footgun { needle: "requests", class: "SSRF", hint: "requests.get on user-supplied URLs reaches internal hosts.", weight: 0.75 },
    Footgun { needle: "spring", class: "SpEL injection / mass assignment / actuator exposure", hint: "SpEL on input, @ModelAttribute over-binding, exposed actuators.", weight: 0.8 },
    Footgun { needle: "snakeyaml", class: "unsafe deserialization", hint: "SnakeYAML default constructor instantiates arbitrary classes.", weight: 0.9 },
    Footgun { needle: "jackson", class: "unsafe deserialization", hint: "polymorphic typing (enableDefaultTyping) is a gadget RCE.", weight: 0.85 },
    Footgun { needle: "fastjson", class: "unsafe deserialization", hint: "autoType enables gadget-chain RCE.", weight: 0.9 },
    Footgun { needle: "react", class: "XSS", hint: "dangerouslySetInnerHTML with untrusted HTML.", weight: 0.6 },
    Footgun { needle: "angular", class: "XSS", hint: "bypassSecurityTrust* defeats the sanitizer.", weight: 0.6 },
];

pub fn footguns_for(dep_name: &str) -> Vec<Footgun> {
    let lower = dep_name.to_lowercase();
    FOOTGUNS.iter().filter(|f| lower.contains(f.needle)).copied().collect()
}

/// Deterministic proposals from manifest footguns (one per dep×class, deduped).
pub fn propose(target: &TargetConfig, max: usize) -> Vec<Proposal> {
    let stack = detect_stack(&target.source_root);
    let mut props = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for dep in &stack.deps {
        for fg in footguns_for(&dep.name) {
            // dedup by (dependency, class): PyYAML matches both "pyyaml" and "yaml"
            // needles for the same class — propose it once.
            if !seen.insert((dep.name.to_lowercase(), fg.class.to_string())) {
                continue;
            }
            let version = if dep.version.is_empty() { String::new() } else { format!(" {}", dep.version) };
            let focus = format!(
                "DEPENDENCY FOOTGUN. The project depends on `{}`{} — a known source of {}: {} Find every call site of `{}` in the code and audit each for {}.",
                dep.name, version, fg.class, fg.hint, dep.name, fg.class,
            );
            props.push(Proposal::new(
                "threat-intel",
                format!("Hunt {} in {} usage", fg.class, dep.name),
                format!("`{}`{} is associated with {}.", dep.name, version, fg.class),
                ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
                fg.weight,
            ));
        }
    }
    props.sort_by(|a, b| b.yield_score.partial_cmp(&a.yield_score).unwrap_or(std::cmp::Ordering::Equal));
    props.truncate(max);
    props
}

/// Optional: a web-research agent looks up live CVEs/advisories for the detected
/// dependencies and emits extra hunts. Best-effort — returns [] if the local CLI
/// lacks web tools.
pub async fn research(target: &TargetConfig, model: &str, max: usize) -> Vec<Proposal> {
    let stack = detect_stack(&target.source_root);
    if stack.deps.is_empty() {
        return Vec::new();
    }
    let dep_list = stack.deps.iter().take(60).map(|d| if d.version.is_empty() { d.name.clone() } else { format!("{} {}", d.name, d.version) }).collect::<Vec<_>>().join("\n");
    let sys = match build_system_prompt(target, "default") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("dependencies".into(), dep_list);
    let prompt = match load_prompt("intel_research", Some(&target.target_dir), "default", &vars) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let mut opts = AgentOpts::new(model);
    opts.cwd = Some(target.source_root.clone());
    opts.tools = Some(vec!["WebSearch".into(), "WebFetch".into(), "Read".into(), "Grep".into(), "Glob".into()]);
    opts.system_prompt = Some(sys.text);
    let agent = run_agent(&prompt.text, &opts).await;

    let mut props = Vec::new();
    for block in parse_all_tags(&agent.all_text(), "hunt") {
        // class | dep | hint | weight
        let p: Vec<&str> = block.splitn(4, '|').map(|x| x.trim()).collect();
        if p.len() < 2 || p[0].is_empty() {
            continue;
        }
        let (class, dep) = (p[0], p[1]);
        let hint = p.get(2).copied().unwrap_or("");
        let weight = p.get(3).and_then(|w| w.parse::<f64>().ok()).unwrap_or(0.8).clamp(0.0, 1.0);
        let focus = format!(
            "CVE-DRIVEN HUNT (live research). {} in `{}`. {} Find the vulnerable usage in this codebase and confirm exploitability.",
            class, dep, hint
        );
        props.push(Proposal::new(
            "threat-intel",
            format!("CVE hunt: {} in {}", class, dep),
            format!("Live advisory research flagged {} for `{}`.", class, dep),
            ProposalSpec { focus_areas: vec![focus], runs: 1, ..Default::default() },
            weight,
        ));
    }
    props.truncate(max);
    props
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_json() {
        let deps = parse_package_json(r#"{"dependencies":{"lodash":"^4.17.15","express":"4.18.0"},"devDependencies":{"jest":"29"}}"#);
        assert!(deps.iter().any(|d| d.name == "lodash" && d.version == "4.17.15"));
        assert!(deps.iter().any(|d| d.name == "express"));
        assert!(deps.iter().any(|d| d.name == "jest"));
    }

    #[test]
    fn parses_requirements_and_cargo() {
        let reqs = parse_requirements_txt("flask==2.0.1\nPyYAML>=5.4  # comment\n-r other.txt\nrequests");
        assert!(reqs.iter().any(|d| d.name == "flask" && d.version == "2.0.1"));
        assert!(reqs.iter().any(|d| d.name == "PyYAML"));
        assert!(reqs.iter().any(|d| d.name == "requests"));
        assert!(!reqs.iter().any(|d| d.name.starts_with('-')));

        let cargo = parse_cargo_toml("[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.35\", features = [\"full\"] }\n[dev-dependencies]\nmockito = \"1\"");
        assert!(cargo.iter().any(|d| d.name == "serde"));
        assert!(cargo.iter().any(|d| d.name == "tokio" && d.version == "1.35"));
    }

    #[test]
    fn footgun_table_maps_known_libs() {
        assert!(footguns_for("lodash").iter().any(|f| f.class == "prototype pollution"));
        assert!(footguns_for("PyYAML").iter().any(|f| f.class == "unsafe deserialization"));
        assert!(footguns_for("spring-web").iter().any(|f| f.class.contains("SpEL")));
        assert!(footguns_for("some-unknown-lib").is_empty());
    }
}
