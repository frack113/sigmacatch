// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Canonical SigmaHQ `info.yml` indentation.
//!
//! `serde_yaml` does not indent block sequences the way SigmaHQ's committed
//! regression data does. These helpers compare an on-disk document with the
//! canonical form produced by [`crate::InfoYml::canonical_yaml`] and rewrite
//! only its indentation, leaving comments and values verbatim.

/// Compact structural key of a YAML line, ignoring indent and value:
/// `(key, is_list_item)` from e.g. `    - id: x` → `("id", true)`.
pub fn yaml_template(line: &str) -> Option<(String, bool)> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let is_list = t.starts_with('-') && (t.starts_with("- ") || t.len() == 1);
    let body = if is_list {
        t.trim_start_matches('-').trim_start()
    } else {
        t
    };
    let key = body.split(':').next().unwrap_or("").trim();
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), is_list))
}

/// `(template, indent)` pairs of a YAML document (comments/blank lines excluded).
pub fn yaml_lines(content: &str) -> Vec<((String, bool), usize)> {
    content
        .lines()
        .filter_map(|l| {
            let indent = l.len() - l.trim_start().len();
            yaml_template(l).map(|t| (t, indent))
        })
        .collect()
}

/// Canonical indent for a template in the canonical document.
pub fn canonical_indent(canonical: &str, template: &(String, bool)) -> Option<usize> {
    yaml_lines(canonical)
        .into_iter()
        .find(|(t, _)| t == template)
        .map(|(_, i)| i)
}

/// Whether any significant line's indent differs from canonical, requiring a fix.
pub fn needs_reindent(raw: &str, canonical: &str) -> bool {
    let canonical_lines = yaml_lines(canonical);
    yaml_lines(raw).into_iter().any(|(template, indent)| {
        canonical_lines
            .iter()
            .find(|(t, _)| *t == template)
            .map(|(_, i)| i != &indent)
            .unwrap_or(true)
    })
}

/// Re-indent a YAML document to canonical 4-space SigmaHQ style while
/// preserving `#` comment lines, blank lines, and values verbatim.
pub fn reindent_yaml(raw: &str, canonical: &str) -> String {
    let canonical_lines = yaml_lines(canonical);
    let mut out = Vec::new();
    for line in raw.lines() {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        let Some((key, is_list)) = yaml_template(line) else {
            out.push(line.to_string());
            continue;
        };
        let indent = canonical_lines
            .iter()
            .find(|(t2, _)| *t2 == (key.clone(), is_list))
            .map(|(_, i)| *i)
            .unwrap_or(0);
        if is_list {
            // Dash at the canonical indent, content aligned two columns after.
            out.push(format!(
                "{}- {}",
                " ".repeat(indent),
                t.trim_start_matches('-').trim_start()
            ));
        } else {
            out.push(format!("{}{}", " ".repeat(indent), t));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reindent_yaml_preserves_comments() {
        let raw = "# top comment\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nrule_metadata:\n- id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n  title: R\n";
        let canonical = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nrule_metadata:\n    - id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n      title: R\n";
        let out = reindent_yaml(raw, canonical);
        assert!(
            out.starts_with("# top comment\n"),
            "comment preserved, got: {out}"
        );
        assert!(
            out.contains("    - id: bbbbbbbb-"),
            "list re-indented, got: {out}"
        );
        assert!(
            out.contains("      title: R"),
            "content re-indented, got: {out}"
        );
    }

    #[test]
    fn needs_reindent_detects_a_shifted_list_item() {
        let raw = "rule_metadata:\n- id: x\n";
        let canonical = "rule_metadata:\n    - id: x\n";
        assert!(needs_reindent(raw, canonical));
        assert!(!needs_reindent(canonical, canonical));
    }

    #[test]
    fn yaml_template_ignores_comments_and_blank_lines() {
        assert_eq!(yaml_template("# note"), None);
        assert_eq!(yaml_template("   "), None);
        assert_eq!(yaml_template("    - id: x"), Some(("id".to_string(), true)));
        assert_eq!(
            yaml_template("  path: a.json"),
            Some(("path".to_string(), false))
        );
    }
}
