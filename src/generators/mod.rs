//! Permutation generators — signal sources that **propose** (never fire) priced
//! permutations into the queue. Each turns evidence about the target into ranked
//! `queue::Proposal`s; the human gate (`cmd_permute`) decides what actually runs.
//!
//!   commits     — git history: defect-prediction hotspots + incomplete-fix hunts
//!   threatmodel — the repo trust-graph: per-flow / per-goal deep scans
//!   intel       — dependency manifests + framework footguns (+ optional research)
//!   evolve      — breed prompt variants against the benchmark fitness function

pub mod commits;
pub mod evolve;
pub mod intel;
pub mod threatmodel;
