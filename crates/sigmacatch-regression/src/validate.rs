// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

/// Validate a rule ID format (lowercase alphanumeric, hyphens, underscores).
pub fn validate_rule_id(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rule_id_valid_uuid() {
        assert!(validate_rule_id("7595ba94-cf3b-4471-aa03-4f6baa9e5fad"));
    }

    #[test]
    fn test_validate_rule_id_valid_alphanumeric() {
        assert!(validate_rule_id("proc_creation_win_bitsadmin_download"));
    }

    #[test]
    fn test_validate_rule_id_invalid() {
        assert!(!validate_rule_id("INVALID_ID!"));
        assert!(!validate_rule_id(""));
        assert!(!validate_rule_id("with spaces"));
    }
}
