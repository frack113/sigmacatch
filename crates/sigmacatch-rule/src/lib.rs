// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Sigma rule management: loading, filtering, scanning, AST indexing.

pub use rsigma_parser::{
    parse_sigma_yaml, Detections, Level, LogSource, SigmaCollection, SigmaRule, Status,
};

pub use crate::loader::{load_all_rules, LoadFilter, LoadResult, LoadStats, MinLevel, MinStatus};
pub use crate::rule_index::RuleIndex;
pub use crate::scanner::find_rules_dirs;

pub mod channel_resolver;
pub mod loader;
pub mod rule_index;
pub mod scanner;
