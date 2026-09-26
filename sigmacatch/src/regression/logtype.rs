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

/// `type` spellings the SigmaHQ regression specification accepts.
///
/// The upstream runner (`regression_data/tests/regression_tests_runner.py`)
/// dispatches `json`/`ndjson`/`jsonl` to its JSON checker and `evtx` to the
/// EVTX checker, then skips every other value as an unknown test type.
pub const SIGMA_SPEC_TYPES: [&str; 4] = ["evtx", "json", "ndjson", "jsonl"];

/// True when `declared` is a `type` the SigmaHQ regression spec accepts.
///
/// sigmacatch stores line-oriented Linux data as `log` and unprocessed Cisco
/// output as `raw`; both are sigmacatch extensions, so entries declaring them
/// validate here but are invisible to the upstream runner.
pub fn is_sigma_spec_type(declared: &str) -> bool {
    SIGMA_SPEC_TYPES.contains(&declared)
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

    #[test]
    fn spec_types_match_the_upstream_runner() {
        for ty in SIGMA_SPEC_TYPES {
            assert!(is_sigma_spec_type(ty), "{ty} must stay spec-valid");
        }
        // sigmacatch extensions: valid locally, rejected upstream.
        assert!(!is_sigma_spec_type("log"));
        assert!(!is_sigma_spec_type("raw"));
        assert!(!is_sigma_spec_type("EVTX"));
        assert!(!is_sigma_spec_type("ndjson "));
        assert!(!is_sigma_spec_type(""));
    }

    /// The spec accepts `ndjson`/`jsonl`, which `from_declared` must keep
    /// refusing: they are spec spellings that resolve to no `LogType`, and
    /// mapping them onto `Json` would make a legacy `ndjson` declaration over
    /// an `.evtx` path parse an EVTX blob as JSON and fail as "EMPTY".
    #[test]
    fn from_declared_keeps_rejecting_ndjson_and_jsonl() {
        assert_eq!(LogType::from_declared("ndjson"), None);
        assert_eq!(LogType::from_declared("jsonl"), None);
        assert_eq!(LogType::from_declared("evtx"), Some(LogType::Evtx));
        assert_eq!(LogType::from_declared("json"), Some(LogType::Json));
    }
}
