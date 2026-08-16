// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! MITRE ATT&CK technique extraction from a rule's `attack.*` tags.

use rsigma_parser::SigmaRule;

/// Extension trait providing ATT&CK technique extraction for Sigma rules.
pub trait SigmaRuleExt {
    /// Extract MITRE ATT&CK technique IDs from a rule's tags.
    ///
    /// Returns sub-technique tags (e.g. "t1071.004") first, then tactical
    /// group tags (e.g. "command-and-control"), with the "attack." prefix
    /// stripped.
    fn attack_techniques(&self) -> Vec<String>;
}

impl SigmaRuleExt for SigmaRule {
    fn attack_techniques(&self) -> Vec<String> {
        let mut sub_techs: Vec<String> = Vec::new();
        let mut groups: Vec<String> = Vec::new();
        for tag in &self.tags {
            if let Some(rest) = tag.strip_prefix("attack.") {
                if rest.starts_with('t') {
                    sub_techs.push(rest.to_string());
                } else if !rest.starts_with('g')
                    && !rest.starts_with('s')
                    && !rest.starts_with(|c: char| c.is_ascii_digit())
                {
                    // tactical group tag (e.g. "command-and-control"), skip g/s IDs
                    groups.push(rest.to_string());
                }
            }
        }
        sub_techs.extend(groups);
        sub_techs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{SigmaCollection, parse_sigma_yaml};

    const RULE: &str = r#"title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: stable
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
  condition: selection
"#;

    fn rule_with_tags(tags: &[&str]) -> SigmaRule {
        let mut content = RULE.to_string();
        if !tags.is_empty() {
            content.push_str("tags:\n");
            for tag in tags {
                content.push_str(&format!("  - {tag}\n"));
            }
        }
        let parsed: SigmaCollection = parse_sigma_yaml(&content).unwrap();
        parsed.rules.into_iter().next().unwrap()
    }

    #[test]
    fn test_attack_techniques_ordering() {
        let rule = rule_with_tags(&[
            "attack.execution",
            "attack.t1055.001",
            "attack.command-and-control",
            "attack.t1055",
        ]);
        let techs = rule.attack_techniques();
        assert_eq!(
            techs,
            vec!["t1055.001", "t1055", "execution", "command-and-control"]
        );
    }

    #[test]
    fn test_attack_techniques_skips_non_technique_ids() {
        let rule = rule_with_tags(&[
            "attack.execution",
            "attack.t1071.004",
            "attack.g0046",
            "attack.s0444",
            "attack.t1071",
        ]);
        let techs = rule.attack_techniques();
        assert_eq!(techs, vec!["t1071.004", "t1071", "execution"]);
    }

    #[test]
    fn test_attack_techniques_only_non_attack_tags() {
        let rule = rule_with_tags(&["tlp.clear", "cve.2021-44228"]);
        assert!(rule.attack_techniques().is_empty());
    }

    #[test]
    fn test_attack_techniques_sub_technique_then_group() {
        let rule = rule_with_tags(&["attack.t1055", "attack.t1055.001", "attack.discovery"]);
        let techs = rule.attack_techniques();
        assert_eq!(techs, vec!["t1055", "t1055.001", "discovery"]);
    }
}
