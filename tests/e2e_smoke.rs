//! End-to-end tests for the orchestration core.
//!
//! Drive the real `cannon` binary against a STUB `claude` CLI (wired in via
//! `CANNON_CLAUDE_BIN`) that replays canned stream-json. This exercises the
//! salvo runner, the agent subprocess driver, the verifier, the ledger merge,
//! the timeout, and `--resume` — paths that have no unit coverage because they
//! shell out to `claude` — without a real model or API credentials.
//!
//! Unix-only: the stub is a `/bin/sh` script.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ── stub responses ──────────────────────────────────────────────────────────

/// A full finding + REAL verdict, so it flows to a confirmed ledger entry.
fn responses_with_finding() -> String {
    let finding = "<finding>\
<title>SQL injection in handler</title>\
<severity>HIGH</severity>\
<cwe>CWE-89 SQL Injection</cwe>\
<file>app.py</file>\
<line>10</line>\
<description>request param flows into a raw SQL query</description>\
<evidence>db.execute(\"... \" + request.args['q'])</evidence>\
<exploit_premise>send a crafted q parameter</exploit_premise>\
<taint_status>reachable</taint_status>\
</finding>\n\
<verdict>REAL</verdict>\n<confidence>0.9</confidence>\n\
<reasoning>request param reaches db.execute unsanitized</reasoning>";
    stream_lines(finding, false)
}

/// A successful result carrying no findings (clean focus area).
fn responses_no_findings() -> String {
    stream_lines("No issues found in this focus area.", false)
}

/// A CLI error result (`is_error: true`) with NO session init — so the agent
/// can't resume and fails fast (exercises graceful error handling, not the
/// retry/backoff loop, which a session-bearing error would trigger).
fn responses_error() -> String {
    let lines = [
        serde_json::json!({"type":"assistant","message":{"content":[{"type":"text","text":"transient failure"}]}}),
        serde_json::json!({"type":"result","subtype":"error","is_error": true,"total_cost_usd":0.0}),
    ];
    lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n") + "\n"
}

/// Build the three stream-json lines the CLI emits for one invocation.
fn stream_lines(assistant_text: &str, is_error: bool) -> String {
    let lines = [
        serde_json::json!({"type":"system","subtype":"init","session_id":"stub-session-1"}),
        serde_json::json!({"type":"assistant","message":{"content":[{"type":"text","text": assistant_text}]}}),
        serde_json::json!({"type":"result","subtype":"success","is_error": is_error,"total_cost_usd":0.0012,"usage":{"input_tokens":11,"output_tokens":22}}),
    ];
    lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n") + "\n"
}

// ── harness ─────────────────────────────────────────────────────────────────

struct Fixture {
    root: PathBuf,
    targets: PathBuf,
    results: PathBuf,
    target: PathBuf,
    stub: PathBuf,
}

fn write_exec(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    let mut perm = std::fs::metadata(path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm).unwrap();
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Set up an isolated target + a stub `claude`. `stub_body` is the shell script
/// the binary runs as `claude`; most tests just `cat` a canned responses file.
fn setup(name: &str, stub_body: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!("cannon_e2e_{}_{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let targets = root.join("targets");
    let results = root.join("results");
    let target = targets.join("smoke");
    std::fs::create_dir_all(target.join("src")).unwrap();
    std::fs::write(
        target.join("config.yaml"),
        "detector: static_review\nlanguage: Python\nfocus_areas:\n  - \"request handlers in app.py\"\n",
    )
    .unwrap();
    std::fs::write(
        target.join("src").join("app.py"),
        "import db\nq = request.args['q']\ndb.execute('select * from t where x=' + q)\n",
    )
    .unwrap();
    let stub = root.join("claude_stub.sh");
    write_exec(&stub, stub_body);
    Fixture { root, targets, results, target, stub }
}

impl Fixture {
    /// A stub that replays `responses` (written to a file the stub cats).
    fn with_responses(name: &str, responses: &str) -> Fixture {
        // setup() wipes+creates the root, so write the responses file AFTER it.
        let f = setup(name, "#!/bin/sh\n");
        let resp = f.root.join("responses.jsonl");
        std::fs::write(&resp, responses).unwrap();
        write_exec(&f.stub, &format!("#!/bin/sh\ncat {}\n", resp.display()));
        f
    }

    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let bin = env!("CARGO_BIN_EXE_cannon");
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env("CANNON_CLAUDE_BIN", &self.stub)
            .env("CANNON_TARGETS", &self.targets)
            .env("CANNON_RESULTS", &self.results)
            .env("CANNON_PROMPTS", manifest_dir().join("prompts"))
            .env("CANNON_AGENT_TIMEOUT_SECS", "60");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().expect("failed to run cannon binary")
    }

    fn ledger(&self) -> Option<serde_json::Value> {
        let p = self.target.join(".cannon").join("ledger.json");
        std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok())
    }

    fn latest_results_dir(&self) -> Option<PathBuf> {
        let run_root = self.results.join("smoke");
        std::fs::read_dir(&run_root).ok()?.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).max()
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

#[test]
fn fire_runs_salvo_and_writes_confirmed_ledger() {
    let f = Fixture::with_responses("happy", &responses_with_finding());
    let out = f.run(&["fire", "smoke", "--runs", "1", "--votes", "1"], &[]);
    let (so, se) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "fire failed\nstdout:\n{so}\nstderr:\n{se}");

    let salvo_found = std::fs::read_dir(f.results.join("smoke"))
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.path().join("salvo.json").exists());
    assert!(salvo_found, "no salvo.json checkpoint written");

    let ledger = f.ledger().expect("ledger.json");
    let findings = ledger["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "ledger has no findings; stdout:\n{so}");
    assert_eq!(findings[0]["status"], "confirmed", "should be confirmed by REAL verdict: {}", findings[0]);
    f.cleanup();
}

#[test]
fn agent_error_is_handled_gracefully() {
    // Every agent call returns is_error:true — cannon must not crash; the run
    // completes with no confirmed findings rather than panicking.
    let f = Fixture::with_responses("agenterr", &responses_error());
    let out = f.run(&["fire", "smoke", "--runs", "1", "--votes", "1"], &[]);
    let se = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "fire should exit 0 even when agents error; stderr:\n{se}");
    // Ledger either absent or has no confirmed findings.
    if let Some(l) = f.ledger() {
        let confirmed = l["findings"].as_array().map(|a| a.iter().filter(|x| x["status"] == "confirmed").count()).unwrap_or(0);
        assert_eq!(confirmed, 0, "agent errors should not yield confirmed findings");
    }
    f.cleanup();
}

#[test]
fn malformed_output_yields_no_findings() {
    // The stub emits a result with no <finding> tags; the run should succeed and
    // produce zero findings (graceful, not a parse panic).
    let f = Fixture::with_responses("malformed", &responses_no_findings());
    let out = f.run(&["fire", "smoke", "--runs", "1", "--votes", "1"], &[]);
    assert!(out.status.success(), "fire should succeed with no findings");
    if let Some(l) = f.ledger() {
        assert!(l["findings"].as_array().map(|a| a.is_empty()).unwrap_or(true), "expected no findings");
    }
    f.cleanup();
}

#[test]
fn timeout_does_not_hang() {
    // A stub that sleeps far longer than the budget. With CANNON_AGENT_TIMEOUT_SECS=1
    // the run must finish promptly (the agent round times out) instead of hanging.
    let f = Fixture::with_responses("timeout", &responses_with_finding());
    // Replace the stub with one that hangs before emitting anything.
    write_exec(&f.stub, "#!/bin/sh\nsleep 30\n");
    let start = std::time::Instant::now();
    let out = f.run(&["fire", "smoke", "--runs", "1", "--votes", "1"], &[("CANNON_AGENT_TIMEOUT_SECS", "1")]);
    let elapsed = start.elapsed();
    assert!(out.status.success(), "fire should complete after the agent times out");
    assert!(elapsed < std::time::Duration::from_secs(25), "run took {elapsed:?} — timeout did not fire");
    f.cleanup();
}

#[test]
fn resume_reuses_checkpoints() {
    // First run produces a checkpointed salvo; the second run with --resume on the
    // same dir reuses the terminal round(s) and still succeeds.
    let f = Fixture::with_responses("resume", &responses_with_finding());
    let out1 = f.run(&["fire", "smoke", "--runs", "1", "--votes", "1"], &[]);
    assert!(out1.status.success(), "first fire failed");
    let rd = f.latest_results_dir().expect("a results dir");

    let out2 = f.run(&["fire", "smoke", "--resume", rd.to_str().unwrap(), "--votes", "1"], &[]);
    let so2 = String::from_utf8_lossy(&out2.stdout);
    let se2 = String::from_utf8_lossy(&out2.stderr);
    assert!(out2.status.success(), "resume failed\nstdout:\n{so2}\nstderr:\n{se2}");
    assert!(
        so2.contains("resume") || so2.contains("skipped") || se2.contains("resume"),
        "expected resume to report reused rounds; stdout:\n{so2}"
    );
    f.cleanup();
}

#[test]
fn resume_refuses_cross_target() {
    // A salvo manifest generated for target 'smoke' must not be resumed against a
    // different target name (versioned-manifest guard).
    let f = Fixture::with_responses("xtarget", &responses_with_finding());
    let out1 = f.run(&["fire", "smoke", "--runs", "1", "--votes", "1"], &[]);
    assert!(out1.status.success());
    let rd = f.latest_results_dir().expect("results dir");

    // Add a second target and try to resume smoke's dir against it.
    let other = f.targets.join("other");
    std::fs::create_dir_all(other.join("src")).unwrap();
    std::fs::write(other.join("config.yaml"), "detector: static_review\nfocus_areas:\n  - x\n").unwrap();
    std::fs::write(other.join("src").join("app.py"), "x = 1\n").unwrap();

    let out2 = f.run(&["fire", "other", "--resume", rd.to_str().unwrap(), "--votes", "1"], &[]);
    assert!(!out2.status.success(), "resuming another target's salvo must be refused");
    let se = String::from_utf8_lossy(&out2.stderr);
    assert!(se.to_lowercase().contains("target") || se.contains("refus"), "expected a cross-target refusal; stderr:\n{se}");
    f.cleanup();
}
