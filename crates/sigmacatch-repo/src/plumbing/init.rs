// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Repository initialization and config writing.

use anyhow::Result;
use std::path::Path;
use tracing::info;

pub(crate) fn git_config_escape(value: &str) -> String {
    if value.contains('"') || value.contains('\\') || value.contains('\n') || value.contains('\r') {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("\"{}\"", escaped)
    } else if value.contains(' ') || value.contains('\t') {
        format!("\"{}\"", value)
    } else {
        value.to_string()
    }
}

/// Initialize a bare `.git` directory with config and HEAD.
pub fn init_repo(git_dir: &Path, _work_tree: &Path, remote_url: &str) -> Result<()> {
    std::fs::create_dir_all(git_dir.join("objects").join("pack"))?;
    std::fs::create_dir_all(git_dir.join("refs").join("heads"))?;
    std::fs::create_dir_all(git_dir.join("refs").join("tags"))?;

    let escaped_url = git_config_escape(remote_url);
    let config = format!(
        "\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote \"origin\"]
\turl = {}
\tfetch = +refs/heads/*:refs/remotes/origin/*
[user]
\tname = sigmacatch
\temail = sigmacatch@localhost
",
        escaped_url
    );
    std::fs::write(git_dir.join("config"), config)?;
    std::fs::write(git_dir.join("description"), b"SigmaHQ rules repository\n")?;

    // HEAD must exist before any grit-lib operation
    std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n")?;

    info!("Initialized git repository");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_config_escape_simple_value() {
        let result = git_config_escape("sigmacatch");
        assert_eq!(result, "sigmacatch");
    }

    #[test]
    fn test_git_config_escape_value_with_quotes() {
        let result = git_config_escape("hello \"world\"");
        assert_eq!(result, "\"hello \\\"world\\\"\"");
    }

    #[test]
    fn test_git_config_escape_value_with_backslashes() {
        let result = git_config_escape(r"C:\Users\foo");
        assert_eq!(result, "\"C:\\\\Users\\\\foo\"");
    }

    #[test]
    fn test_git_config_escape_value_with_newlines() {
        let result = git_config_escape("line1\nline2");
        assert_eq!(result, "\"line1\\nline2\"");
    }

    #[test]
    fn test_git_config_escape_value_with_spaces() {
        let result = git_config_escape("hello world");
        assert_eq!(result, "\"hello world\"");
    }
}
