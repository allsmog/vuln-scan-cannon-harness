//! Target configuration loader (port of config.py).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct TargetConfig {
    pub name: String,
    pub target_dir: PathBuf,
    pub source_root: PathBuf,
    pub detector: String,
    pub language: Option<String>,
    pub description: Option<String>,
    pub focus_areas: Vec<String>,
    pub engagement_context: Option<String>,
    // dynamic detector
    pub build_command: Option<String>,
    pub run_command: Option<String>,
    pub witness: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    source_root: Option<String>,
    #[serde(default)]
    detector: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    focus_areas: Option<Vec<String>>,
    #[serde(default)]
    engagement_context: Option<String>,
    #[serde(default)]
    build_command: Option<String>,
    #[serde(default)]
    run_command: Option<String>,
    #[serde(default)]
    witness: Option<String>,
}

impl TargetConfig {
    pub fn context_dir(&self) -> PathBuf {
        self.target_dir.join("context")
    }

    pub fn load(target: &str, targets_root: &str) -> Result<TargetConfig> {
        let mut p = PathBuf::from(target);
        if !p.exists() {
            p = PathBuf::from(targets_root).join(target);
        }
        let p = p
            .canonicalize()
            .with_context(|| format!("resolving target '{target}'"))?;
        let config_path = p.join("config.yaml");
        if !config_path.exists() {
            bail!("No config.yaml in {}", p.display());
        }
        let raw: RawConfig = serde_yaml_ng::from_str(&std::fs::read_to_string(&config_path)?)
            .with_context(|| format!("parsing {}", config_path.display()))?;

        let source_root = match &raw.source_root {
            Some(sr) => {
                let s = PathBuf::from(sr);
                if s.is_absolute() {
                    s
                } else {
                    p.join(s)
                }
            }
            None => {
                if p.join("src").is_dir() {
                    p.join("src")
                } else {
                    p.clone()
                }
            }
        };
        let source_root = source_root.canonicalize().unwrap_or(source_root);

        let engagement = match &raw.engagement_context {
            Some(e) if !e.contains('\n') && p.join(e).exists() => {
                Some(std::fs::read_to_string(p.join(e))?.trim().to_string())
            }
            other => other.clone(),
        };

        let name = p.file_name().unwrap().to_string_lossy().to_string();
        Ok(TargetConfig {
            name,
            target_dir: p,
            source_root,
            detector: raw.detector.unwrap_or_else(|| "static_review".into()),
            language: raw.language,
            description: raw.description,
            focus_areas: raw.focus_areas.unwrap_or_default(),
            engagement_context: engagement,
            build_command: raw.build_command,
            run_command: raw.run_command,
            witness: raw.witness,
        })
    }
}
