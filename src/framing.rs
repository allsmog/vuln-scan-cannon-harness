//! System-prompt construction, shared by every stage agent (port of framing.py).

use crate::config::TargetConfig;
use crate::prompts::{load_prompt, PromptRender};
use anyhow::Result;
use std::collections::BTreeMap;

pub const DEFAULT_ENGAGEMENT: &str =
    "This is authorized defensive security research: a static source-code \
review of a codebase the operator owns or is permitted to assess. Findings \
are collected for remediation. You only read source — you never execute the target.";

pub fn build_system_prompt(target: &TargetConfig, variant: &str) -> Result<PromptRender> {
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert(
        "engagement".to_string(),
        target.engagement_context.clone().unwrap_or_else(|| DEFAULT_ENGAGEMENT.to_string()),
    );
    vars.insert(
        "language".to_string(),
        target.language.clone().unwrap_or_else(|| "unspecified".to_string()),
    );
    load_prompt("system", Some(&target.target_dir), variant, &vars)
}
