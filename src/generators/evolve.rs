//! Evolution (#1) — breed prompt variants instead of hand-writing them.
//!
//! Each variant is a genome; its **fitness** is how many findings it gets
//! *confirmed* when fired at the target (in-vivo selection — bred to be good at
//! THIS codebase). The loop: bootstrap by evaluating the seed variants, then
//! select the fittest as parents, have an agent **mutate** their find-prompt into
//! offspring, and propose evaluating those. Fitness flows back via the queue's
//! recorded outcomes (`record_fitness`).
//!
//! Selection + offspring planning are pure and unit-tested; only mutation uses an
//! agent.

use crate::agent::{parse_xml_tag, run_agent, AgentOpts};
use crate::config::TargetConfig;
use crate::framing::build_system_prompt;
use crate::prompts::{load_prompt, prompts_dir, resolve_prompt_path};
use crate::queue::{Proposal, ProposalSpec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Genome {
    pub name: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub generation: usize,
    /// in-vivo fitness (e.g. confirmed findings); None = not yet evaluated
    #[serde(default)]
    pub fitness: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvoState {
    #[serde(default)]
    pub generation: usize,
    #[serde(default)]
    pub genomes: Vec<Genome>,
}

impl EvoState {
    fn path(target_dir: &Path) -> std::path::PathBuf {
        target_dir.join(".cannon").join("evolution.json")
    }
    pub fn load(target_dir: &Path) -> EvoState {
        std::fs::read_to_string(Self::path(target_dir)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    pub fn save(&self, target_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(target_dir.join(".cannon"))?;
        let j = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(Self::path(target_dir), j)
    }
    pub fn get(&self, name: &str) -> Option<&Genome> {
        self.genomes.iter().find(|g| g.name == name)
    }
}

/// The hand-written variants are generation 0.
pub fn seed_genomes() -> Vec<Genome> {
    ["default", "aggressive"].iter().map(|n| Genome { name: n.to_string(), parent: None, generation: 0, fitness: None }).collect()
}

/// Top-`k` evaluated genomes by fitness (desc), tie-broken by name. Pure.
pub fn select_parents(genomes: &[Genome], k: usize) -> Vec<Genome> {
    let mut evaluated: Vec<Genome> = genomes.iter().filter(|g| g.fitness.is_some()).cloned().collect();
    evaluated.sort_by(|a, b| {
        b.fitness.partial_cmp(&a.fitness).unwrap_or(std::cmp::Ordering::Equal).then(a.name.cmp(&b.name))
    });
    evaluated.truncate(k);
    evaluated
}

/// Plan `n` offspring from the fittest parents (round-robin parentage for
/// diversity). Offspring are unevaluated, generation+1. Pure.
pub fn plan_offspring(state: &EvoState, n: usize) -> Vec<Genome> {
    let parents = select_parents(&state.genomes, 3.min(n.max(1)));
    if parents.is_empty() {
        return Vec::new();
    }
    let gen = state.generation + 1;
    (0..n)
        .map(|i| Genome {
            name: format!("g{gen}-{i}"),
            parent: Some(parents[i % parents.len()].name.clone()),
            generation: gen,
            fitness: None,
        })
        .collect()
}

fn eval_proposal(name: &str, parent_desc: &str, yield_score: f64) -> Proposal {
    Proposal::new(
        "evolution",
        format!("Evaluate evolved variant '{name}' ({parent_desc})"),
        format!("Breed step: fire variant '{name}' at the target; confirmed findings become its fitness."),
        // whole-target, single round, with the verifier so "confirmed" is meaningful
        ProposalSpec { focus_areas: vec![], variants: vec![name.to_string()], models: vec![], runs: 1, verify: true, votes: 1 },
        yield_score,
    )
}

/// Have an agent mutate the parent's find-prompt into a new strategy, written to
/// `prompts/variants/<child>/find.md`. Returns Ok(()) on success.
async fn mutate_variant(target: &TargetConfig, parent: &str, child: &str, model: &str) -> anyhow::Result<()> {
    let parent_path = resolve_prompt_path("find", Some(&target.target_dir), parent)?;
    let parent_prompt = std::fs::read_to_string(&parent_path)?;
    let sys = build_system_prompt(target, "default")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("parent_name".into(), parent.to_string());
    vars.insert("parent_prompt".into(), parent_prompt);
    let prompt = load_prompt("evolve_mutate", Some(&target.target_dir), "default", &vars)?;

    let mut opts = AgentOpts::new(model);
    opts.system_prompt = Some(sys.text);
    let agent = run_agent(&prompt.text, &opts).await;
    let body = parse_xml_tag(&agent.all_text(), "variant_prompt").ok_or_else(|| anyhow::anyhow!("agent emitted no <variant_prompt>"))?;
    if body.len() < 80 || !body.contains("<finding>") {
        anyhow::bail!("mutated prompt looks malformed (no <finding> contract)");
    }
    let dir = prompts_dir().join("variants").join(child);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("find.md"), body)?;
    Ok(())
}

/// Fold a finished evaluation's fitness back into the genome (keeps the best).
pub fn record_fitness(target_dir: &Path, name: &str, fitness: f64) {
    let mut state = EvoState::load(target_dir);
    if let Some(g) = state.genomes.iter_mut().find(|g| g.name == name) {
        g.fitness = Some(g.fitness.map_or(fitness, |f| f.max(fitness)));
    } else {
        state.genomes.push(Genome { name: name.to_string(), parent: None, generation: state.generation, fitness: Some(fitness) });
    }
    let _ = state.save(target_dir);
}

/// Propose the next evolution step: bootstrap (evaluate seeds) until parents
/// exist, then breed offspring from the fittest.
pub async fn propose(target: &TargetConfig, model: &str, n_offspring: usize, max: usize) -> Vec<Proposal> {
    let mut state = EvoState::load(&target.target_dir);
    if state.genomes.is_empty() {
        state.genomes = seed_genomes();
        let _ = state.save(&target.target_dir);
    }
    let mut props = Vec::new();

    if !state.genomes.iter().any(|g| g.fitness.is_some()) {
        // bootstrap: get baseline fitness for the seed variants
        for g in state.genomes.clone() {
            props.push(eval_proposal(&g.name, "seed — baseline fitness", 0.7));
        }
    } else {
        // breed
        let plan = plan_offspring(&state, n_offspring);
        let best = select_parents(&state.genomes, 1).first().and_then(|g| g.fitness).unwrap_or(1.0).max(1.0);
        for child in plan {
            let parent = child.parent.clone().unwrap_or_else(|| "default".into());
            match mutate_variant(target, &parent, &child.name, model).await {
                Ok(()) => {
                    let pf = state.get(&parent).and_then(|g| g.fitness).unwrap_or(0.0);
                    props.push(eval_proposal(&child.name, &format!("mutated from '{parent}'"), 0.55 + 0.4 * (pf / best)));
                    state.genomes.push(child);
                }
                Err(e) => eprintln!("  [evolve] skipped {}: {e}", child.name),
            }
        }
        state.generation += 1;
        let _ = state.save(&target.target_dir);
    }
    props.truncate(max);
    props
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(name: &str, fitness: Option<f64>) -> Genome {
        Genome { name: name.into(), parent: None, generation: 0, fitness }
    }

    #[test]
    fn select_parents_takes_fittest_evaluated() {
        let pop = vec![g("a", Some(3.0)), g("b", None), g("c", Some(5.0)), g("d", Some(1.0))];
        let parents = select_parents(&pop, 2);
        assert_eq!(parents.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), vec!["c", "a"]);
        // unevaluated genome 'b' is never a parent
        assert!(!parents.iter().any(|g| g.name == "b"));
    }

    #[test]
    fn plan_offspring_names_and_parents() {
        let state = EvoState { generation: 1, genomes: vec![g("aggressive", Some(8.0)), g("default", Some(4.0))] };
        let kids = plan_offspring(&state, 3);
        assert_eq!(kids.len(), 3);
        assert_eq!(kids[0].name, "g2-0");
        assert_eq!(kids[0].generation, 2);
        // round-robin parentage over the (≤3) fittest parents
        assert_eq!(kids[0].parent.as_deref(), Some("aggressive"));
        assert_eq!(kids[1].parent.as_deref(), Some("default"));
        assert!(kids.iter().all(|k| k.fitness.is_none()));
    }

    #[test]
    fn plan_offspring_empty_without_evaluated_parents() {
        let state = EvoState { generation: 0, genomes: vec![g("default", None)] };
        assert!(plan_offspring(&state, 2).is_empty());
    }
}
