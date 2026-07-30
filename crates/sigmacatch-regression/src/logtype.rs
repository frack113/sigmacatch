// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

/// Data format of a regression entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogType {
    Evtx,
    Json,
    Raw,
    Log,
}

impl LogType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Evtx => "evtx",
            Self::Json => "json",
            Self::Raw => "raw",
            Self::Log => "log",
        }
    }
}

impl std::fmt::Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
