// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::{Level, Status};

/// Counters describing one rule-loading pass.
#[derive(Debug, Clone, Default)]
pub struct LoadStats {
    /// Rules kept after all filters.
    pub rules_loaded: u64,
    /// Rules dropped by the product filter.
    pub rules_filtered_product: u64,
    /// Rules dropped by the status filter.
    pub rules_filtered_status: u64,
    /// Rules dropped by the level filter.
    pub rules_filtered_level: u64,
    /// Rules dropped by the author filter.
    pub rules_filtered_author: u64,
    /// Total rules seen before filtering.
    pub rules_total_candidate: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Minimum acceptable rule status (ordinal: stable > test > experimental > …).
#[serde(transparent)]
pub struct MinStatus(pub Status);

impl MinStatus {
    fn rank(&self) -> u8 {
        match self.0 {
            Status::Unsupported => 0,
            Status::Deprecated => 1,
            Status::Experimental => 2,
            Status::Test => 3,
            Status::Stable => 4,
        }
    }

    /// True when a rule with `rule_status` passes this threshold.
    pub fn accepts(&self, rule_status: &Status) -> bool {
        let rule_rank = match rule_status {
            Status::Unsupported => 0,
            Status::Deprecated => 1,
            Status::Experimental => 2,
            Status::Test => 3,
            Status::Stable => 4,
        };
        rule_rank >= self.rank()
    }
}

impl Default for MinStatus {
    fn default() -> Self {
        MinStatus(Status::Stable)
    }
}

impl PartialOrd for MinStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for MinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            Status::Unsupported => "unsupported",
            Status::Deprecated => "deprecated",
            Status::Experimental => "experimental",
            Status::Test => "test",
            Status::Stable => "stable",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Minimum acceptable rule level (ordinal: critical > high > … > informational).
#[serde(transparent)]
pub struct MinLevel(pub Level);

impl MinLevel {
    fn rank(&self) -> u8 {
        match self.0 {
            Level::Informational => 0,
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
            Level::Critical => 4,
        }
    }

    /// True when a rule with `rule_level` passes this threshold.
    pub fn accepts(&self, rule_level: &Level) -> bool {
        let rule_rank = match rule_level {
            Level::Informational => 0,
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
            Level::Critical => 4,
        };
        rule_rank >= self.rank()
    }
}

impl Default for MinLevel {
    fn default() -> Self {
        MinLevel(Level::Critical)
    }
}

impl PartialOrd for MinLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for MinLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            Level::Informational => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_status_serde_roundtrip_lowercase() {
        let yaml = serde_yaml::to_string(&MinStatus(Status::Stable)).unwrap();
        assert_eq!(yaml.trim(), "stable");
        let parsed: MinStatus = serde_yaml::from_str("experimental").unwrap();
        assert_eq!(parsed, MinStatus(Status::Experimental));
    }

    #[test]
    fn test_min_level_serde_roundtrip_lowercase() {
        let yaml = serde_yaml::to_string(&MinLevel(Level::Critical)).unwrap();
        assert_eq!(yaml.trim(), "critical");
        let parsed: MinLevel = serde_yaml::from_str("high").unwrap();
        assert_eq!(parsed, MinLevel(Level::High));
    }

    #[test]
    fn test_min_status_default_stable() {
        assert_eq!(MinStatus::default(), MinStatus(Status::Stable));
        assert_eq!(MinLevel::default(), MinLevel(Level::Critical));
    }

    #[test]
    fn test_min_status_ordinal_order() {
        assert!(MinStatus(Status::Stable) > MinStatus(Status::Test));
        assert!(MinStatus(Status::Test) > MinStatus(Status::Experimental));
        assert!(MinStatus(Status::Experimental) > MinStatus(Status::Deprecated));
        assert!(MinStatus(Status::Deprecated) > MinStatus(Status::Unsupported));
        assert!(MinStatus(Status::Unsupported) >= MinStatus(Status::Unsupported));
    }

    #[test]
    fn test_min_level_ordinal_order() {
        assert!(MinLevel(Level::Critical) > MinLevel(Level::High));
        assert!(MinLevel(Level::High) > MinLevel(Level::Medium));
        assert!(MinLevel(Level::Medium) > MinLevel(Level::Low));
        assert!(MinLevel(Level::Low) > MinLevel(Level::Informational));
    }

    #[test]
    fn test_min_status_display_lowercase() {
        assert_eq!(MinStatus(Status::Stable).to_string(), "stable");
        assert_eq!(MinLevel(Level::Critical).to_string(), "critical");
    }
}
