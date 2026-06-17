//! End-to-end smoke test for the orchestration core.
//!
//! Drives the real `cannon` binary against a STUB `claude` CLI (wired in via
//! `CANNON_CLAUDE_BIN`) that replays canned stream-json. This exercises the
//! salvo runner, the agent subprocess driver, the verifier, and the ledger
//! merge — the paths that have no unit coverage because they shell out to
//! `claude` — without needing a real model or API credentials.
//!
//! Unix-only: the stub is a `/bin/sh` script.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// One stream-json line as the `claude -p --output-format stream-json` CLI emits.
fn responses_jsonl() -> String {
    // The stub replays the same lines for every agent call. The find stage reads
    // the <finding> block; the verifier reads <verdict>/<confidence>. Emitting
    // both means a finding flows all the way to a confirmed ledger entry.
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
<taint_path>\nsource | app.py:3 | request.args['q']\nsink | app.py:10 | db.execute\n</taint_path>\
</finding>\n\
<verdict>REAL</verdict>\n<confidence>0.9</confidence>\n\
<access_level>unauthenticated_remote</access_level>\n\
<reachability>app.py:3 -> app.py:10</reachability>\n\
<reasoning>request param reaches db.execute unsanitized</reasoning>";

    let lines = [
        serde_json::json!({"type":"system","subtype":"init","session_id":"stub-session-1"}),
        serde_json::json!({"type":"assistant","message":{"content":[{"type":"text","text": finding}]}}),
        serde_json::json!({"type":"result","subtype":"success","is_error":false,"total_cost_usd":0.0012,"usage":{"input_tokens":11,"output_tokens":22}}),
    ];
    lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n") + "\n"
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

#[test]
fn fire_runs_salvo_and_writes_confirmed_ledger() {
    let root = std::env::temp_dir().join(format!("cannon_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let targets = root.join("targets");
    let results = root.join("results");
    let target = targets.join("smoke");
    std::fs::create_dir_all(target.join("src")).unwrap();

    // Minimal target: one focus area, source under the target dir (passes containment).
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

    // Stub claude: replay canned stream-json regardless of args.
    let responses = root.join("responses.jsonl");
    std::fs::write(&responses, responses_jsonl()).unwrap();
    let stub = root.join("claude_stub.sh");
    write_exec(&stub, &format!("#!/bin/sh\ncat {}\n", responses.display()));

    let bin = env!("CARGO_BIN_EXE_cannon");
    let output = Command::new(bin)
        .args(["fire", "smoke", "--runs", "1", "--votes", "1"])
        .env("CANNON_CLAUDE_BIN", &stub)
        .env("CANNON_TARGETS", &targets)
        .env("CANNON_RESULTS", &results)
        .env("CANNON_PROMPTS", manifest_dir().join("prompts"))
        .env("CANNON_AGENT_TIMEOUT_SECS", "60")
        .output()
        .expect("failed to run cannon binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "cannon fire failed (status {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );

    // A per-run results dir was created under results/smoke/<ts>/.
    let run_root = results.join("smoke");
    assert!(run_root.is_dir(), "no results dir created under {}", run_root.display());
    let salvo_found = std::fs::read_dir(&run_root)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.path().join("salvo.json").exists());
    assert!(salvo_found, "no salvo.json checkpoint written");

    // The finding merged into the persistent ledger and verified REAL → confirmed.
    let ledger_path = target.join(".cannon").join("ledger.json");
    assert!(ledger_path.is_file(), "ledger.json not written");
    let ledger: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    let findings = ledger["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "ledger has no findings; stdout:\n{stdout}");
    let f = &findings[0];
    assert!(
        f["title"].as_str().unwrap_or("").to_lowercase().contains("sql"),
        "unexpected finding title: {f}"
    );
    assert_eq!(f["status"], "confirmed", "finding should be confirmed by the REAL verdict: {f}");

    let _ = std::fs::remove_dir_all(&root);
}
