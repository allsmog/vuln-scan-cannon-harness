//! Prompt loader — the mutation surface (port of prompts.py).
//!
//! Resolution order (highest first):
//!   1. <target>/prompt_overrides/<name>.md
//!   2. <prompts>/variants/<variant>/<name>.md
//!   3. <prompts>/<name>.md
//!
//! sha256 is over the RAW template (the version id), independent of interpolation.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn prompts_dir() -> PathBuf {
    std::env::var("CANNON_PROMPTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("prompts"))
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // name/variant are kept for provenance/debugging
pub struct PromptRender {
    pub name: String,
    pub text: String,
    pub sha256: String,
    pub source: String,
    pub variant: String,
}

pub fn resolve_prompt_path(name: &str, target_dir: Option<&Path>, variant: &str) -> Result<PathBuf> {
    let base = prompts_dir();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(td) = target_dir {
        candidates.push(td.join("prompt_overrides").join(format!("{name}.md")));
    }
    if variant != "default" {
        candidates.push(base.join("variants").join(variant).join(format!("{name}.md")));
    }
    candidates.push(base.join(format!("{name}.md")));
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    bail!(
        "No prompt '{}' found (looked in: {})",
        name,
        candidates.iter().map(|c| c.display().to_string()).collect::<Vec<_>>().join(", ")
    )
}

/// Replace `{key}` tokens with values; unknown `{tokens}` are left intact.
fn interpolate(raw: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = raw.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

pub fn load_prompt(
    name: &str,
    target_dir: Option<&Path>,
    variant: &str,
    vars: &BTreeMap<String, String>,
) -> Result<PromptRender> {
    let path = resolve_prompt_path(name, target_dir, variant)?;
    let raw = std::fs::read_to_string(&path)?;
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let sha = format!("{:x}", hasher.finalize());
    let sha = sha[..16].to_string();
    Ok(PromptRender {
        name: name.to_string(),
        text: interpolate(&raw, vars),
        sha256: sha,
        source: path.display().to_string(),
        variant: variant.to_string(),
    })
}
