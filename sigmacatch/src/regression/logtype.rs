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

    /// Parse a declared `type` (or a data-file extension). `None` for anything
    /// outside the four known spellings so callers can tell "unknown" from a
    /// real `json` entry instead of silently accepting a typo.
    pub fn from_declared(declared: &str) -> Option<Self> {
        match declared {
            "evtx" => Some(Self::Evtx),
            "json" => Some(Self::Json),
            "raw" => Some(Self::Raw),
            "log" => Some(Self::Log),
            _ => None,
        }
    }
}

impl std::fmt::Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_and_display_match_sigma_logtype_spelling() {
        for logtype in [LogType::Evtx, LogType::Json, LogType::Raw, LogType::Log] {
            assert_eq!(logtype.to_string(), logtype.as_str());
            assert!(logtype.as_str().is_ascii());
        }
        assert_eq!(LogType::Evtx.as_str(), "evtx");
        assert_eq!(LogType::Json.as_str(), "json");
        assert_eq!(LogType::Raw.as_str(), "raw");
        assert_eq!(LogType::Log.as_str(), "log");
    }
}
