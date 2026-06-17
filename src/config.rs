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

        // Containment: a target's config.yaml must not silently redirect cannon's
        // read/exec scope outside the target dir (and the working tree). When you
        // scan code you didn't author, a hostile `source_root: /etc` (or `~/.ssh`)
        // would otherwise point the scanner — and the dynamic detector's `sh -c`
        // commands — anywhere on disk. Default-deny; opt in explicitly.
        if std::env::var("CANNON_ALLOW_EXTERNAL_SOURCE_ROOT").ok().as_deref() != Some("1") {
            let cwd = std::env::current_dir().ok();
            let within_target = source_root.starts_with(&p);
            let within_cwd = cwd.as_ref().map(|c| source_root.starts_with(c)).unwrap_or(false);
            if !within_target && !within_cwd {
                bail!(
                    "source_root '{}' resolves outside the target dir ({}) and the working dir.\n\
                     A config.yaml redirecting cannon's scan scope elsewhere is a security risk \
                     (you may be scanning untrusted code).\n\
                     Set CANNON_ALLOW_EXTERNAL_SOURCE_ROOT=1 to allow it deliberately.",
                    source_root.display(),
                    p.display()
                );
            }
        }

        let engagement = match &raw.engagement_context {
            Some(e) if !e.contains('\n') && p.join(e).exists() => {
                Some(std::fs::read_to_string(p.join(e))?.trim().to_string())
            }
            other => other.clone(),
        };

        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| target.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_source_root_outside_target_by_default() {
        let base = std::env::temp_dir().join(format!("cannon_cfg_ext_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tdir = base.join("t");
        std::fs::create_dir_all(&tdir).unwrap();
        std::fs::write(tdir.join("config.yaml"), "detector: static_review\nsource_root: /etc\n").unwrap();
        let r = TargetConfig::load(tdir.to_str().unwrap(), "targets");
        assert!(r.is_err(), "a config.yaml pointing source_root at /etc must be refused by default");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn accepts_default_src_within_target() {
        let base = std::env::temp_dir().join(format!("cannon_cfg_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tdir = base.join("t");
        std::fs::create_dir_all(tdir.join("src")).unwrap();
        std::fs::write(tdir.join("config.yaml"), "detector: static_review\n").unwrap();
        let r = TargetConfig::load(tdir.to_str().unwrap(), "targets");
        assert!(r.is_ok(), "default src/ within the target dir must load: {:?}", r.err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
