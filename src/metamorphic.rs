//! Metamorphic verification — prove the safe-vs-vulnerable distinction by
//! perturbation, the way a human reviewer does.
//!
//! A "safe lookalike" (the OWASP false-positive trap, a guarded sink) is safe
//! because of one *load-bearing* fact: a helper returns a constant, a validator
//! runs first, a branch is unreachable. You confirm that by asking: **what minimal
//! change would make this exploitable, and does the real code already differ
//! exactly there?**
//!
//!   - If the bug fires in the code as-written → it's REAL.
//!   - If the code is safe but a minimal mutation (removing the constant/guard)
//!     makes it fire → the safety is load-bearing and effective → the finding is a
//!     FALSE_POSITIVE (the control works; the "exploit" claim is wrong).
//!   - If even the mutation doesn't produce the bug → the probe was uninformative
//!     → INCONCLUSIVE.
//!
//! This module is the deterministic core: the decision function, the reconcile
//! rule, and a tested file-mutation helper for the optional execution-grounded
//! path (it reuses `dynamic::reproduce` to actually run original vs. mutant).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetamorphicVerdict {
    Real,
    FalsePositive,
    Inconclusive,
}

impl MetamorphicVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            MetamorphicVerdict::Real => "REAL",
            MetamorphicVerdict::FalsePositive => "FALSE_POSITIVE",
            MetamorphicVerdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// The differential decision. `orig_vulnerable` = does the bug exhibit in the
/// code as written; `mutant_vulnerable` = does it exhibit once the suspected
/// load-bearing control is removed.
pub fn decide(orig_vulnerable: bool, mutant_vulnerable: bool) -> MetamorphicVerdict {
    match (orig_vulnerable, mutant_vulnerable) {
        // present as-written → real regardless of the mutant
        (true, _) => MetamorphicVerdict::Real,
        // safe now, but removing the control creates the bug → the control is
        // real and load-bearing → the finding's exploitability claim is false
        (false, true) => MetamorphicVerdict::FalsePositive,
        // the mutation didn't even create the bug → the probe proved nothing
        (false, false) => MetamorphicVerdict::Inconclusive,
    }
}

/// How a metamorphic verdict should adjust a finding's ledger status (the caller
/// still enforces stickiness — never overriding a human decision). `Inconclusive`
/// changes nothing.
pub fn reconcile(v: MetamorphicVerdict) -> Option<&'static str> {
    match v {
        MetamorphicVerdict::FalsePositive => Some("false_positive"),
        MetamorphicVerdict::Real => Some("confirmed"),
        MetamorphicVerdict::Inconclusive => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetamorphicReport {
    pub id: String,
    pub signature: String,
    pub verdict: String, // MetamorphicVerdict::as_str
    pub orig_vulnerable: bool,
    pub mutant_vulnerable: bool,
    /// the minimal change that would flip safe↔vulnerable
    #[serde(default)]
    pub mutation: String,
    #[serde(default)]
    pub reasoning: String,
    /// true when the booleans came from actually executing original vs. mutant
    #[serde(default)]
    pub executed: bool,
}

impl MetamorphicReport {
    pub fn verdict_enum(&self) -> MetamorphicVerdict {
        match self.verdict.as_str() {
            "REAL" => MetamorphicVerdict::Real,
            "FALSE_POSITIVE" => MetamorphicVerdict::FalsePositive,
            _ => MetamorphicVerdict::Inconclusive,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Execution-grounded path (optional): synthesize the mutant on disk and run both.
// ──────────────────────────────────────────────────────────────────────────────

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in walkdir::WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
        let rel = match entry.path().strip_prefix(src) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Join `rel` under `base`, refusing absolute paths, drive prefixes, and any
/// `..` traversal. `rel_file` is ultimately LLM-derived (steerable by target
/// content), so an un-contained join (`dst.join("../../etc/passwd")`) would be an
/// arbitrary read+rewrite primitive once exec is enabled.
fn safe_join(base: &Path, rel: &str) -> std::io::Result<PathBuf> {
    use std::path::Component;
    let relp = Path::new(rel);
    for comp in relp.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing unsafe mutation_file path '{rel}'"),
                ))
            }
        }
    }
    Ok(base.join(relp))
}

/// Sanitize a tag for use as a single path segment (temp dir name).
fn safe_tag(tag: &str) -> String {
    let s: String = tag.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    if s.is_empty() { "x".into() } else { s.chars().take(64).collect() }
}

/// Copy `src_root` into a fresh temp dir, then apply a literal `find`→`replace` in
/// `rel_file`. Returns the temp root (caller cleans it up). The mutation is the
/// agent's "what would make this vulnerable" change; we materialize it to run it.
pub fn stage_mutation(src_root: &Path, rel_file: &str, find: &str, replace: &str, tag: &str) -> std::io::Result<PathBuf> {
    let dst = std::env::temp_dir().join(format!("cannon_meta_{}", safe_tag(tag)));
    let _ = std::fs::remove_dir_all(&dst);
    copy_tree(src_root, &dst)?;
    let f = safe_join(&dst, rel_file)?;
    let original = std::fs::read_to_string(&f)?;
    if !find.is_empty() && original.contains(find) {
        std::fs::write(&f, original.replacen(find, replace, 1))?;
    }
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_truth_table() {
        assert_eq!(decide(true, true), MetamorphicVerdict::Real);
        assert_eq!(decide(true, false), MetamorphicVerdict::Real);
        assert_eq!(decide(false, true), MetamorphicVerdict::FalsePositive);
        assert_eq!(decide(false, false), MetamorphicVerdict::Inconclusive);
    }

    #[test]
    fn reconcile_maps_verdicts() {
        assert_eq!(reconcile(MetamorphicVerdict::FalsePositive), Some("false_positive"));
        assert_eq!(reconcile(MetamorphicVerdict::Real), Some("confirmed"));
        assert_eq!(reconcile(MetamorphicVerdict::Inconclusive), None);
    }

    #[test]
    fn stage_mutation_copies_and_rewrites_one_file() {
        let src = std::env::temp_dir().join("cannon_meta_src_test");
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("app.py"), "value = getTheValue()  # returns \"bar\"\n").unwrap();
        std::fs::write(src.join("sub/other.py"), "untouched\n").unwrap();

        let mutant = stage_mutation(&src, "app.py", "getTheValue()", "request.param", "unit").unwrap();
        let got = std::fs::read_to_string(mutant.join("app.py")).unwrap();
        assert!(got.contains("request.param"));
        assert!(!got.contains("getTheValue()"));
        // other files are copied verbatim
        assert_eq!(std::fs::read_to_string(mutant.join("sub/other.py")).unwrap(), "untouched\n");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&mutant);
    }

    #[test]
    fn safe_join_blocks_traversal_and_absolute() {
        let base = Path::new("/tmp/cannon_base");
        // Legitimate relative paths are allowed.
        assert!(safe_join(base, "app.py").is_ok());
        assert!(safe_join(base, "sub/other.py").is_ok());
        assert!(safe_join(base, "./a.py").is_ok());
        // Traversal and absolute escapes are refused.
        assert!(safe_join(base, "../../etc/passwd").is_err());
        assert!(safe_join(base, "sub/../../escape").is_err());
        assert!(safe_join(base, "/etc/passwd").is_err());
    }

    #[test]
    fn stage_mutation_refuses_traversal_rel_file() {
        let src = std::env::temp_dir().join("cannon_meta_trav_test");
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("app.py"), "x\n").unwrap();
        let err = stage_mutation(&src, "../../../../../../etc/hosts", "x", "y", "trav");
        assert!(err.is_err(), "traversal rel_file must be refused");
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn safe_tag_strips_path_separators() {
        assert_eq!(safe_tag("F-001"), "F-001");
        assert_eq!(safe_tag("../../evil"), "______evil");
        assert!(!safe_tag("a/b/c").contains('/'));
        assert_eq!(safe_tag(""), "x");
    }

    #[test]
    fn report_roundtrips_verdict_enum() {
        let r = MetamorphicReport {
            id: "F-001".into(),
            signature: "app.py:30:89".into(),
            verdict: "FALSE_POSITIVE".into(),
            orig_vulnerable: false,
            mutant_vulnerable: true,
            mutation: "getTheValue() -> request.param".into(),
            reasoning: "constant is load-bearing".into(),
            executed: false,
        };
        assert_eq!(r.verdict_enum(), MetamorphicVerdict::FalsePositive);
        assert_eq!(reconcile(r.verdict_enum()), Some("false_positive"));
    }
}
