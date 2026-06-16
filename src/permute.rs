//! The permutation matrix — the 'cannon' part (port of permute.py).
//!
//! One target, fired at from many angles: focus × variant × model × repeats.

use crate::artifacts::slugify;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spec {
    pub round_idx: usize,
    pub label: String,
    pub focus_area: Option<String>,
    pub variant: String,
    pub model: String,
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
