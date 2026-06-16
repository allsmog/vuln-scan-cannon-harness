//! Claude Code headless CLI wrapper — host edition (port of agent.py).
//!
//! Runs `claude -p` on the host with a read-only toolset, streams its
//! stream-json output, and resumes a dead process with exponential backoff.
//! The local `claude` CLI is assumed already authenticated.

use crate::ui::ecolor;
use regex::Regex;
use serde_json::Value;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

pub const READONLY_TOOLS: [&str; 3] = ["Read", "Grep", "Glob"];

// Process-wide cost/token accounting, summed from each agent's `result` message.
use std::sync::atomic::{AtomicU64, Ordering};
static TOTAL_COST_MICRO: AtomicU64 = AtomicU64::new(0);
static TOTAL_IN: AtomicU64 = AtomicU64::new(0);
static TOTAL_OUT: AtomicU64 = AtomicU64::new(0);

pub fn total_cost_usd() -> f64 {
    TOTAL_COST_MICRO.load(Ordering::Relaxed) as f64 / 1_000_000.0
}
pub fn total_tokens() -> (u64, u64) {
    (TOTAL_IN.load(Ordering::Relaxed), TOTAL_OUT.load(Ordering::Relaxed))
}

#[derive(Clone)]
pub struct AgentOpts {
    pub model: String,
    pub cwd: Option<PathBuf>,
    pub add_dirs: Vec<String>,
    pub tools: Option<Vec<String>>,
    pub system_prompt: Option<String>,
    pub transcript_path: Option<PathBuf>,
    pub progress_prefix: Option<String>,
    pub max_resume_attempts: u32,
}

impl AgentOpts {
    pub fn new(model: &str) -> Self {
        AgentOpts {
            model: model.to_string(),
            cwd: None,
            add_dirs: Vec::new(),
            tools: None,
            system_prompt: None,
            transcript_path: None,
            progress_prefix: None,
            max_resume_attempts: 12,
        }
    }
}

#[derive(Default)]
pub struct AgentResult {
    pub messages: Vec<Value>,
    pub session_id: Option<String>,
    pub error: Option<String>,
    pub resume_count: u32,
}

fn blocks_to_text(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(arr) = content.as_array() {
        return arr
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
    }
    String::new()
}

impl AgentResult {
    /// Most-recent assistant message containing <tag>; falls back to last.
    pub fn find_tagged_message(&self, tag: &str) -> String {
        let needle = format!("<{tag}>");
        let mut last_assistant = String::new();
        for msg in self.messages.iter().rev() {
            if msg.get("type").and_then(|t| t.as_str()) != Some("assistant") {
                continue;
            }
            let text = blocks_to_text(&msg["message"]["content"]);
            if last_assistant.is_empty() {
                last_assistant = text.clone();
            }
            if text.contains(&needle) {
                return text;
            }
        }
        last_assistant
    }

    /// Concatenation of every assistant text block.
    pub fn all_text(&self) -> String {
        self.messages
            .iter()
            .filter(|m| m.get("type").and_then(|t| t.as_str()) == Some("assistant"))
            .map(|m| blocks_to_text(&m["message"]["content"]))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub fn parse_xml_tag(text: &str, tag: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?s)<{0}>(.*?)</{0}>", regex::escape(tag))).ok()?;
    re.captures_iter(text)
        .last()
        .map(|c| c[1].trim().to_string())
}

pub fn parse_all_tags(text: &str, tag: &str) -> Vec<String> {
    let re = match Regex::new(&format!(r"(?s)<{0}>(.*?)</{0}>", regex::escape(tag))) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    re.captures_iter(text).map(|c| c[1].trim().to_string()).collect()
}

fn progress_line(msg: &Value, prefix: &str) {
    if msg.get("type").and_then(|t| t.as_str()) != Some("assistant") {
        return;
    }
    let content = match msg["message"]["content"].as_array() {
        Some(a) => a,
        None => return,
    };
    for b in content {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("tool_use") => {
                let name = b.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let inp = &b["input"];
                let arg = inp
                    .get("command")
                    .or_else(|| inp.get("file_path"))
                    .or_else(|| inp.get("path"))
                    .or_else(|| inp.get("pattern"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let arg: String = arg.replace('\n', " ").chars().take(120).collect();
                eprintln!("{}", ecolor(&format!("{prefix}   → {name}: {arg}"), "dim"));
            }
            Some("text") => {
                let t = b.get("text").and_then(|v| v.as_str()).unwrap_or("").trim().replace('\n', " ");
                if !t.is_empty() {
                    let t: String = t.chars().take(140).collect();
                    eprintln!("{}", ecolor(&format!("{prefix}   · {t}"), "dim"));
                }
            }
            _ => {}
        }
    }
}

pub async fn run_agent(prompt: &str, opts: &AgentOpts) -> AgentResult {
    let tools: Vec<String> = opts
        .tools
        .clone()
        .unwrap_or_else(|| READONLY_TOOLS.iter().map(|s| s.to_string()).collect());

    let mut result = AgentResult::default();
    let mut attempt: u32 = 0;
    let mut transcript = opts
        .transcript_path
        .as_ref()
        .and_then(|p| std::fs::File::create(p).ok());

    loop {
        let mut cmd = Command::new("claude");
        cmd.arg("-p")
            .arg("--verbose")
            .arg("--output-format")
            .arg("stream-json")
            .arg("--permission-mode")
            .arg("bypassPermissions")
            .arg("--model")
            .arg(&opts.model);
        if !tools.is_empty() {
            cmd.arg("--tools");
            for t in &tools {
                cmd.arg(t);
            }
        }
        for d in &opts.add_dirs {
            cmd.arg("--add-dir").arg(d);
        }
        if let Some(sp) = &opts.system_prompt {
            cmd.arg("--append-system-prompt").arg(sp);
        }
        if attempt > 0 && result.session_id.is_some() {
            cmd.arg("--resume").arg(result.session_id.as_ref().unwrap()).arg("continue");
        } else {
            cmd.arg(prompt);
        }
        if let Some(cwd) = &opts.cwd {
            cmd.current_dir(cwd);
        }
        cmd.env("IS_SANDBOX", "1").env("CLAUDECODE", "");
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                result.error = Some(format!("spawn failed: {e}"));
                return result;
            }
        };

        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take();
        let stderr_handle = tokio::spawn(async move {
            let mut buf = String::new();
            if let Some(e) = stderr.as_mut() {
                let _ = e.read_to_string(&mut buf).await;
            }
            buf
        });

        let mut lines = BufReader::new(stdout).lines();
        let mut got_result = false;
        let mut errored: Option<String> = None;

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let msg: Value = match serde_json::from_str(line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(f) = transcript.as_mut() {
                        let _ = writeln!(f, "{line}");
                    }
                    if let Some(prefix) = &opts.progress_prefix {
                        progress_line(&msg, prefix);
                    }
                    let mtype = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if mtype == "system"
                        && msg.get("subtype").and_then(|t| t.as_str()) == Some("init")
                    {
                        if result.session_id.is_none() {
                            if let Some(sid) = msg.get("session_id").and_then(|s| s.as_str()) {
                                result.session_id = Some(sid.to_string());
                            }
                        }
                        result.messages.push(msg);
                    } else if mtype == "result" {
                        if let Some(c) = msg.get("total_cost_usd").and_then(|v| v.as_f64()) {
                            TOTAL_COST_MICRO.fetch_add((c * 1_000_000.0) as u64, Ordering::Relaxed);
                        }
                        if let Some(u) = msg.get("usage") {
                            if let Some(i) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                                TOTAL_IN.fetch_add(i, Ordering::Relaxed);
                            }
                            if let Some(o) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                                TOTAL_OUT.fetch_add(o, Ordering::Relaxed);
                            }
                        }
                        let is_err = msg.get("is_error").and_then(|b| b.as_bool()).unwrap_or(false);
                        result.messages.push(msg);
                        if is_err {
                            errored = Some("CLI result is_error".to_string());
                        } else {
                            got_result = true;
                        }
                        break;
                    } else {
                        result.messages.push(msg);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        let _ = child.wait().await;
        let stderr_text = stderr_handle.await.unwrap_or_default();

        if got_result && errored.is_none() {
            return result;
        }

        attempt += 1;
        let err = errored.unwrap_or_else(|| {
            let tail: String = stderr_text.chars().rev().take(400).collect::<String>().chars().rev().collect();
            format!("CLI exited without result: {tail}")
        });
        if result.session_id.is_none() || attempt > opts.max_resume_attempts {
            result.error = Some(format!("{err} after {attempt} attempt(s)"));
            return result;
        }
        let backoff = std::cmp::min(2u64.pow(attempt.min(20)), 300);
        eprintln!(
            "{}",
            ecolor(
                &format!(
                    "[agent] {err} on attempt {attempt}, resuming {} in {backoff}s",
                    result.session_id.as_deref().unwrap_or("?")
                ),
                "dim"
            )
        );
        result.resume_count = attempt;
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
    }
}
