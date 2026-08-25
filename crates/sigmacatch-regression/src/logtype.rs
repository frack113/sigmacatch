// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// SigmaHQ log type recorded in `info.yml`.
pub enum LogType {
    /// Windows event log binary format.
    Evtx,
    /// JSON-serialized events.
    Json,
    /// Unprocessed raw bytes.
    Raw,
    /// Line-oriented text (auditd/syslog) regression data.
    Log,
}

impl LogType {
    /// Lowercase SigmaHQ `logtype` spelling.
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
