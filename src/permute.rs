//! The permutation matrix — the 'cannon' part (port of permute.py).
//!
//! One target, fired at from many angles: focus × variant × model × repeats.

use crate::artifacts::slugify;
use serde::{Deserialize, Serialize};

/// On-disk schema version for salvo manifests and round checkpoints. Bump when
/// the format changes incompatibly so `--resume` can refuse stale/foreign dirs.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spec {
    pub round_idx: usize,
    pub label: String,
    pub focus_area: Option<String>,
    pub variant: String,
    pub model: String,
}

/// `salvo.json` — the resume manifest. Carries the schema version and the target
/// it was generated for so `--resume <dir>` can detect a cross-target or
/// schema-drifted directory instead of silently running the wrong specs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SalvoManifest {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub cannon_version: String,
    pub specs: Vec<Spec>,
}

impl SalvoManifest {
    pub fn new(target: &str, specs: Vec<Spec>) -> Self {
        SalvoManifest {
            schema_version: SCHEMA_VERSION,
            target: target.to_string(),
            cannon_version: env!("CARGO_PKG_VERSION").to_string(),
            specs,
        }
    }

    /// Parse `salvo.json`, tolerating the legacy bare-`[Spec,…]` array (schema 0).
    pub fn parse(s: &str) -> anyhow::Result<SalvoManifest> {
        if let Ok(m) = serde_json::from_str::<SalvoManifest>(s) {
            return Ok(m);
        }
        let specs: Vec<Spec> = serde_json::from_str(s)
            .map_err(|e| anyhow::anyhow!("salvo.json is neither a manifest nor a spec list: {e}"))?;
        Ok(SalvoManifest { schema_version: 0, target: String::new(), cannon_version: String::new(), specs })
    }

    /// Verify this manifest is safe to resume for `target_name`. Refuses a
    /// newer-than-known schema or a different target; warns on a legacy schema.
    pub fn check_resumable(&self, target_name: &str) -> anyhow::Result<()> {
        if self.schema_version > SCHEMA_VERSION {
            anyhow::bail!(
                "this salvo was written by a newer cannon (schema v{}, this build understands v{}); \
                 upgrade cannon or start a fresh run",
                self.schema_version, SCHEMA_VERSION
            );
        }
        if !self.target.is_empty() && self.target != target_name {
            anyhow::bail!(
                "refusing to resume: this salvo was generated for target '{}', not '{}'. \
                 Resuming it would run the wrong specs against the wrong code.",
                self.target, target_name
            );
        }
        if self.schema_version < SCHEMA_VERSION {
            eprintln!(
                "  ⚠ resuming a legacy salvo (schema v{} < v{}); proceeding best-effort",
                self.schema_version, SCHEMA_VERSION
            );
        }
        Ok(())
    }
}

fn short_model(m: &str) -> String {
    for tag in ["opus", "sonnet", "haiku"] {
        if m.contains(tag) {
            return tag.to_string();
        }
    }
    slugify(m, 10)
}

pub fn build_matrix(
    focus_areas: &[String],
    variants: &[String],
    models: &[String],
    runs: usize,
) -> Vec<Spec> {
    let focuses: Vec<Option<String>> = if focus_areas.is_empty() {
        vec![None]
    } else {
        focus_areas.iter().map(|f| Some(f.clone())).collect()
    };
    let mut specs = Vec::new();
    let mut idx = 0usize;
    for model in models {
        for variant in variants {
            for focus in &focuses {
                for _ in 0..runs {
                    let mut parts = vec![format!("r{idx:02}")];
                    if let Some(f) = focus {
                        parts.push(slugify(f, 18));
                    }
                    if variant != "default" {
                        parts.push(format!("v={}", slugify(variant, 10)));
                    }
                    if models.len() > 1 {
                        parts.push(short_model(model));
                    }
                    specs.push(Spec {
                        round_idx: idx,
                        label: parts.join("·"),
                        focus_area: focus.clone(),
                        variant: variant.clone(),
                        model: model.clone(),
                    });
                    idx += 1;
                }
            }
        }
    }
    specs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrips_and_carries_identity() {
        let specs = build_matrix(&["a".into()], &["default".into()], &["opus".into()], 1);
        let m = SalvoManifest::new("myтarget", specs);
        let j = serde_json::to_string(&m).unwrap();
        let back = SalvoManifest::parse(&j).unwrap();
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(back.target, "myтarget");
        assert_eq!(back.specs.len(), 1);
    }

    #[test]
    fn parse_tolerates_legacy_bare_array() {
        let specs = build_matrix(&["a".into()], &["default".into()], &["opus".into()], 1);
        let legacy = serde_json::to_string(&specs).unwrap(); // bare [Spec,…]
        let m = SalvoManifest::parse(&legacy).unwrap();
        assert_eq!(m.schema_version, 0);
        assert_eq!(m.specs.len(), 1);
    }

    #[test]
    fn check_resumable_refuses_cross_target_and_newer_schema() {
        let specs = build_matrix(&["a".into()], &["default".into()], &["opus".into()], 1);
        let m = SalvoManifest::new("alpha", specs.clone());
        assert!(m.check_resumable("alpha").is_ok());
        assert!(m.check_resumable("beta").is_err(), "cross-target resume must be refused");

        let newer = SalvoManifest { schema_version: SCHEMA_VERSION + 1, target: "alpha".into(), cannon_version: "9.9".into(), specs };
        assert!(newer.check_resumable("alpha").is_err(), "newer schema must be refused");
    }

    #[test]
    fn check_resumable_allows_legacy_without_target() {
        // Legacy manifest (schema 0, empty target) is best-effort allowed.
        let specs = build_matrix(&["a".into()], &["default".into()], &["opus".into()], 1);
        let legacy = SalvoManifest { schema_version: 0, target: String::new(), cannon_version: String::new(), specs };
        assert!(legacy.check_resumable("anything").is_ok());
    }
}
