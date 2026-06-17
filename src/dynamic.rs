//! Dynamic detector — proof-carrying findings.
//!
//! An agent crafts an input; cannon EXECUTES the target on it and keeps the
//! finding only if an executable WITNESS (crash / marker output) reproduces N×.
//! This executes target code, so it is gated behind `CANNON_ALLOW_EXEC=1` and
//! should be run inside a sandbox / disposable VM.

use crate::agent::{parse_all_tags, run_agent, AgentOpts};
use crate::artifacts::{Finding, RoundResult};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::permute::Spec;
use crate::prompts::load_prompt;
use base64::Engine;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct WitnessResult {
    pub fired: usize,
    pub reps: usize,
    pub sample: String,
    #[allow(dead_code)]
    pub exit: Option<i32>,
}

impl WitnessResult {
    /// Proven if it fires for at least 2/3 of reps (tolerates flaky-but-real).
    pub fn proven(&self) -> bool {
        self.reps > 0 && self.fired * 3 >= self.reps * 2
    }
}

/// Env-var name substrings that likely carry secrets. Removed from the
/// environment of exec'd target commands so a (possibly untrusted) target can't
/// read the operator's credentials out of its own process environment.
const SECRET_ENV_HINTS: [&str; 13] = [
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "AWS_", "GCP_", "AZURE_", "ANTHROPIC", "OPENAI",
];

/// Strip secret-bearing env vars from `cmd` (keeps PATH/HOME/LANG so builds work).
fn harden_exec_env(cmd: &mut Command) {
    for (k, _) in std::env::vars() {
        let up = k.to_uppercase();
        if SECRET_ENV_HINTS.iter().any(|h| up.contains(h)) {
            cmd.env_remove(&k);
        }
    }
}

/// Run `run_command` once with `{input}`/`{src}` substituted; combined output; timeout.
pub fn run_once(run_command: &str, input_path: &str, src: &str, cwd: &Path, timeout: Duration) -> (Option<i32>, String) {
    let cmd = run_command.replace("{input}", input_path).replace("{src}", src);
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(&cmd)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    harden_exec_env(&mut command);
    let mut child = match command
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (Some(-1), format!("spawn error: {e}")),
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut o) = child.stdout.take() {
                    let _ = o.read_to_string(&mut out);
                }
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut out);
                }
                return (status.code(), out);
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (None, "(timeout — killed)".into());
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => return (Some(-1), format!("wait error: {e}")),
        }
    }
}

/// Did the witness fire for this run? Witness grammar:
///   crash              — killed by signal, or shell exit > 128 (default for None)
///   exit_nonzero       — any non-zero / abnormal exit
///   exit_zero          — exit 0
///   exit_code:N        — exact code
///   output_contains:PAT — combined stdout/stderr contains PAT
pub fn check_witness(exit: Option<i32>, output: &str, witness: &str) -> bool {
    let w = witness.trim();
    if let Some(pat) = w.strip_prefix("output_contains:") {
        return output.contains(pat.trim());
    }
    if let Some(code) = w.strip_prefix("exit_code:") {
        return exit == code.trim().parse::<i32>().ok();
    }
    match w {
        "crash" => exit.is_none() || exit.map(|c| c > 128).unwrap_or(true),
        "exit_zero" => exit == Some(0),
        _ => exit != Some(0), // exit_nonzero (default)
    }
}

pub fn reproduce(run_command: &str, input_path: &str, src: &str, cwd: &Path, witness: &str, reps: usize, timeout: Duration) -> WitnessResult {
    let mut fired = 0;
    let mut sample = String::new();
    let mut last_exit = None;
    for _ in 0..reps {
        let (exit, out) = run_once(run_command, input_path, src, cwd, timeout);
        last_exit = exit;
        if check_witness(exit, &out, witness) {
            fired += 1;
            if sample.is_empty() {
                sample = out.chars().take(2000).collect();
            }
        }
    }
    WitnessResult { fired, reps, sample, exit: last_exit }
}

fn round(target: &TargetConfig, spec: &Spec, status: &str, findings: Vec<Finding>, error: Option<String>) -> RoundResult {
    RoundResult {
        target: target.name.clone(),
        label: spec.label.clone(),
        status: status.to_string(),
        focus_area: spec.focus_area.clone(),
        variant: spec.variant.clone(),
        model: spec.model.clone(),
        findings,
        prompt_shas: BTreeMap::new(),
        prompt_sources: BTreeMap::new(),
        timings: BTreeMap::new(),
        session_id: None,
        error,
    }
}

pub async fn run_round(target: &TargetConfig, spec: &Spec, out_dir: &Path, progress_prefix: Option<String>) -> RoundResult {
    if std::env::var("CANNON_ALLOW_EXEC").ok().as_deref() != Some("1") {
        return round(target, spec, "error", vec![], Some(
            "dynamic detector executes target code; set CANNON_ALLOW_EXEC=1 and run inside a sandbox/VM".into(),
        ));
    }
    let run_command = match &target.run_command {
        Some(r) => r.clone(),
        None => return round(target, spec, "error", vec![], Some("dynamic target needs run_command in config.yaml".into())),
    };
    let witness = target.witness.clone().unwrap_or_else(|| "crash".into());
    let src = target.source_root.display().to_string();

    // Make the authorized commands visible: they come from the target's
    // config.yaml and run via `sh -c`. The operator opted in with CANNON_ALLOW_EXEC.
    eprintln!(
        "{}",
        crate::ui::ecolor(
            &format!(
                "  ⚠ exec enabled — running target commands from config.yaml under {}:\n      build: {}\n      run:   {}",
                target.source_root.display(),
                target.build_command.as_deref().unwrap_or("(none)"),
                run_command
            ),
            "dim"
        )
    );

    // Build once (if configured).
    if let Some(bc) = &target.build_command {
        let (exit, out) = run_once(bc, "", &src, &target.source_root, Duration::from_secs(1800));
        if exit != Some(0) {
            return round(target, spec, "build_failed", vec![], Some(format!("build failed (exit {exit:?}): {}", out.chars().take(500).collect::<String>())));
        }
    }

    let _ = std::fs::create_dir_all(out_dir);
    let sys = match build_system_prompt(target, &spec.variant) {
        Ok(s) => s,
        Err(e) => return round(target, spec, "error", vec![], Some(format!("{e}"))),
    };
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("source_root".into(), src.clone());
    vars.insert("run_command".into(), run_command.clone());
    vars.insert("witness".into(), witness.clone());
    vars.insert("focus_area".into(), spec.focus_area.clone().unwrap_or_else(|| "the whole target".into()));
    let prompt = match load_prompt("dynamic_find", Some(&target.target_dir), &spec.variant, &vars) {
        Ok(p) => p,
        Err(e) => return round(target, spec, "error", vec![], Some(format!("{e}"))),
    };

    let mut opts = AgentOpts::new(&spec.model);
    opts.cwd = Some(target.source_root.clone());
    opts.system_prompt = Some(sys.text.clone());
    opts.transcript_path = Some(out_dir.join("dynamic_find_transcript.jsonl"));
    opts.progress_prefix = progress_prefix;
    let agent = run_agent(&prompt.text, &opts).await;
    if let Some(e) = agent.error {
        return round(target, spec, "agent_failed", vec![], Some(e));
    }
    let text = agent.all_text();

    // The agent may propose several candidate inputs; execute each, keep proven ones.
    let mut findings = Vec::new();
    let crash_types = parse_all_tags(&text, "crash_type");
    let files = parse_all_tags(&text, "file");
    let pocs_b64 = parse_all_tags(&text, "poc_b64");
    let pocs_lit = parse_all_tags(&text, "poc");

    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for b in &pocs_b64 {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b.trim()) {
            candidates.push(bytes);
        }
    }
    for l in &pocs_lit {
        candidates.push(l.clone().into_bytes());
    }

    for (i, bytes) in candidates.iter().enumerate() {
        let poc_path = out_dir.join(format!("poc_{i}.bin"));
        if std::fs::write(&poc_path, bytes).is_err() {
            continue;
        }
        // Absolute path: the command runs with cwd = source_root, so a relative
        // PoC path would not resolve.
        let poc_path = std::fs::canonicalize(&poc_path).unwrap_or(poc_path);
        let res = reproduce(&run_command, &poc_path.display().to_string(), &src, &target.source_root, &witness, 3, Duration::from_secs(10));
        if res.proven() {
            findings.push(Finding {
                title: crash_types.get(i).cloned().unwrap_or_else(|| "Reproduced crash".into()),
                severity: "HIGH".into(),
                file: files.get(i).cloned().unwrap_or_else(|| "?".into()),
                line: None,
                cwe: Some("CWE-787".into()),
                description: format!(
                    "PROVEN by execution: the target reproduced the witness '{}' {}/{} times on a crafted input.",
                    witness, res.fired, res.reps
                ),
                evidence: format!("witness output:\n{}", res.sample.chars().take(1200).collect::<String>()),
                exploit_premise: format!("PoC at {} ({} bytes); reproduced {}/{}.", poc_path.display(), bytes.len(), res.fired, res.reps),
                focus_area: spec.focus_area.clone(),
                round_label: Some(spec.label.clone()),
                ..Default::default()
            });
        }
    }

    let status = if findings.is_empty() { "no_findings" } else { "completed" };
    round(target, spec, status, findings, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the real exec path through `sh`, so they only run on Unix.
    #[cfg(unix)]
    fn temp_target(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cannon_dyn_test_{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // a tiny "vulnerable" program: exit 134 (crash-like) iff input contains BOOM
        std::fs::write(dir.join("vuln.sh"), "#!/bin/sh\nif grep -q BOOM \"$1\"; then exit 134; else exit 0; fi\n").unwrap();
        dir
    }

    #[test]
    fn secret_env_hints_match_common_secrets() {
        let secret = ["AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "MY_API_KEY"];
        for k in secret {
            let up = k.to_uppercase();
            assert!(SECRET_ENV_HINTS.iter().any(|h| up.contains(h)), "{k} should be flagged secret");
        }
        let safe = ["PATH", "HOME", "LANG", "TMPDIR", "USER", "SHELL"];
        for k in safe {
            let up = k.to_uppercase();
            assert!(!SECRET_ENV_HINTS.iter().any(|h| up.contains(h)), "{k} should NOT be flagged");
        }
    }

    #[test]
    fn witness_grammar() {
        assert!(check_witness(Some(134), "", "crash"));
        assert!(check_witness(None, "", "crash"));
        assert!(!check_witness(Some(0), "", "crash"));
        assert!(check_witness(Some(1), "", "exit_nonzero"));
        assert!(check_witness(Some(0), "ok", "exit_zero"));
        assert!(check_witness(Some(7), "", "exit_code:7"));
        assert!(check_witness(Some(0), "AddressSanitizer: heap-overflow", "output_contains:AddressSanitizer"));
        assert!(!check_witness(Some(0), "fine", "output_contains:AddressSanitizer"));
    }

    #[cfg(unix)]
    #[test]
    fn reproduce_proven_on_crashing_input() {
        let dir = temp_target("proven");
        let boom = dir.join("boom.txt");
        std::fs::write(&boom, "xxxBOOMxxx").unwrap();
        let res = reproduce("sh vuln.sh {input}", &boom.display().to_string(), &dir.display().to_string(), &dir, "crash", 3, Duration::from_secs(5));
        assert_eq!(res.fired, 3);
        assert!(res.proven());
    }

    #[cfg(unix)]
    #[test]
    fn reproduce_not_proven_on_safe_input() {
        let dir = temp_target("safe");
        let safe = dir.join("safe.txt");
        std::fs::write(&safe, "all good here").unwrap();
        let res = reproduce("sh vuln.sh {input}", &safe.display().to_string(), &dir.display().to_string(), &dir, "crash", 3, Duration::from_secs(5));
        assert_eq!(res.fired, 0);
        assert!(!res.proven());
    }

    #[cfg(unix)]
    #[test]
    fn timeout_is_enforced() {
        let dir = temp_target("timeout");
        let dummy = dir.join("d.txt");
        std::fs::write(&dummy, "x").unwrap();
        let (exit, out) = run_once("sleep 5", &dummy.display().to_string(), &dir.display().to_string(), &dir, Duration::from_millis(200));
        assert!(exit.is_none());
        assert!(out.contains("timeout"));
    }

    #[cfg(unix)]
    #[test]
    fn absolute_input_path_resolves_under_foreign_cwd() {
        // Regression: the PoC path must be absolute, because the target runs with
        // cwd = source_root, not the dir cannon wrote the PoC into.
        let dir = temp_target("cwd");
        let boom = dir.join("boom.txt");
        std::fs::write(&boom, "BOOMBOOM").unwrap();
        let abs = std::fs::canonicalize(&boom).unwrap();
        let other_cwd = std::env::temp_dir();
        let res = reproduce(&format!("sh {}/vuln.sh {{input}}", dir.display()), &abs.display().to_string(), &dir.display().to_string(), &other_cwd, "crash", 2, Duration::from_secs(5));
        assert!(res.proven());
    }
}
