// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::{Context, Result};
use sigmacatch_types::{Alert, RegressionHeader};
use std::path::{Path, PathBuf};
use tracing::info;

use crate::info::InfoYml;

pub trait EvtxWriter {
    fn write_evtx(
        &self,
        xml: &str,
        channel: &str,
        record_id: Option<u64>,
        path: &Path,
    ) -> Result<()>;
}

pub struct RegressionData {
    pub header: RegressionHeader,
    pub alerts: Vec<Alert>,
    pub output_path: PathBuf,
    pub rule_rel_path: Option<PathBuf>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub is_contrib: bool,
}

impl RegressionData {
    pub fn new(
        header: RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
        is_contrib: bool,
    ) -> Self {
        Self {
            header,
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            is_contrib,
        }
    }

    pub fn add_alert(&mut self, alert: Alert) {
        self.alerts.push(alert);
    }

    pub fn rule_dir(&self) -> Result<PathBuf> {
        if let Some(rel_path) = &self.rule_rel_path {
            return Ok(self.output_path.join(rel_path));
        }
        let rule_id = &self.header.rule_id;
        if rule_id.contains('/')
            || rule_id.contains('\\')
            || rule_id.contains("..")
            || rule_id.contains('\0')
        {
            anyhow::bail!(
                "Invalid rule_id '{}': contains forbidden characters",
                rule_id
            );
        }
        Ok(self.output_path.join("rules").join(rule_id))
    }

    pub fn sigma_rel_dir(&self) -> Option<String> {
        self.rule_rel_path.as_ref().map(|rel_path| {
            let rel = rel_path.display().to_string().replace('\\', "/");
            if self.is_contrib {
                format!("sigma/regression_data/{}", rel)
            } else {
                format!("regression_data/{}", rel)
            }
        })
    }

    pub fn exists(&self) -> bool {
        self.rule_dir().is_ok_and(|d| d.join("info.yml").exists())
    }

    pub fn generate(&self, writer: &impl EvtxWriter) -> Result<()> {
        let rule_dir = self.rule_dir()?;
        let rule_id = &self.header.rule_id;
        std::fs::create_dir_all(&rule_dir)
            .with_context(|| format!("Failed to create rule directory {:?}", rule_dir))?;

        let first = self.alerts.first();
        let match_count = if first.is_some() { 1 } else { 0 };

        if let Some(alert) = first {
            let raw_json_path = rule_dir.join(format!("{}.json", rule_id));
            let raw_json = serde_json::to_string_pretty(&alert.event_json)?;
            std::fs::write(&raw_json_path, raw_json)?;
            info!("Wrote JSON for rule {:?}", rule_id);

            let evtx_path = rule_dir.join(format!("{}.evtx", rule_id));
            writer
                .write_evtx(
                    alert.raw_xml(),
                    alert.channel(),
                    alert.record_id(),
                    &evtx_path,
                )
                .with_context(|| format!("Failed to write EVTX for rule {:?}", rule_id))?;
            info!("Wrote EVTX for rule {:?}", rule_id);
        }

        let sigma_evtx_path = if first.is_some() {
            let evtx_name = format!("{}.evtx", rule_id);
            format!("{}/{}", self.sigma_rel_dir().unwrap_or_default(), evtx_name)
        } else {
            String::new()
        };

        let author = self
            .author
            .as_deref()
            .unwrap_or("Sigma Regression Generator");

        let description = self.description.as_deref().unwrap_or("N/A");

        let provider = first
            .map(|a| a.provider())
            .unwrap_or("Microsoft-Windows-Sysmon");

        let info = InfoYml::new(
            rule_id,
            &self.header.rule_title,
            match_count,
            &sigma_evtx_path,
            author,
            description,
            provider,
        );
        let info_path = rule_dir.join("info.yml");
        info.save(&info_path)?;
        info!("Created info.yml at {:?}", info_path);

        info!(
            "Generated {} regression events for rule {:?}",
            self.alerts.len(),
            self.header.rule_id
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sample_alert(rule_id: &str, event_json: serde_json::Value) -> Alert {
        Alert::new(
            rule_id.to_string(),
            rule_id.to_string(),
            "medium".to_string(),
            &sigmacatch_types::Event::new(event_json, b"<xml/>".to_vec()),
        )
    }

    struct MockWriter {
        call_count: AtomicUsize,
    }

    impl MockWriter {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }
    }

    impl EvtxWriter for MockWriter {
        fn write_evtx(
            &self,
            _xml: &str,
            _channel: &str,
            _record_id: Option<u64>,
            path: &Path,
        ) -> Result<()> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            std::fs::write(path, b"mock evtx content")?;
            Ok(())
        }
    }

    fn test_event_json() -> serde_json::Value {
        json!({
            "Event": {
                "System": {
                    "Channel": "Security",
                    "EventID": 4688,
                    "Provider": {
                        "#attributes": {
                            "Name": "Microsoft-Windows-Security-Auditing"
                        }
                    }
                }
            },
            "EventRecordID_num": 42
        })
    }

    #[test]
    fn test_rule_dir_valid() {
        let header = RegressionHeader::new("valid-rule-123".into(), "Test".into());
        let reg = RegressionData::new(header, Path::new("/tmp"), None, None, None, false);
        let dir = reg.rule_dir().unwrap();
        assert_eq!(dir, Path::new("/tmp/rules/valid-rule-123"));
    }

    #[test]
    fn test_rule_dir_with_rel_path() {
        let header = RegressionHeader::new("rule-id".into(), "Test".into());
        let reg = RegressionData::new(
            header,
            Path::new("/tmp"),
            Some(Path::new("rules/windows/test")),
            None,
            None,
            false,
        );
        let dir = reg.rule_dir().unwrap();
        assert_eq!(dir, Path::new("/tmp/rules/windows/test"));
    }

    #[test]
    fn test_rule_dir_invalid_rule_id() {
        let header = RegressionHeader::new("../evil".into(), "Test".into());
        let reg = RegressionData::new(header, Path::new("/tmp"), None, None, None, false);
        assert!(reg.rule_dir().is_err());
    }

    #[test]
    fn test_sigma_rel_dir_contrib() {
        let header = RegressionHeader::new("rule-id".into(), "Test".into());
        let reg = RegressionData::new(
            header,
            Path::new("sigma/regression_data"),
            Some(Path::new("rules/windows/test")),
            None,
            None,
            true,
        );
        assert_eq!(
            reg.sigma_rel_dir().as_deref(),
            Some("sigma/regression_data/rules/windows/test")
        );
    }

    #[test]
    fn test_sigma_rel_dir_non_contrib() {
        let header = RegressionHeader::new("rule-id".into(), "Test".into());
        let reg = RegressionData::new(
            header,
            Path::new("regression_data"),
            Some(Path::new("rules/windows/test")),
            None,
            None,
            false,
        );
        assert_eq!(
            reg.sigma_rel_dir().as_deref(),
            Some("regression_data/rules/windows/test")
        );
    }

    #[test]
    fn test_exists_no_dir() {
        let header = RegressionHeader::new("does-not-exist".into(), "Test".into());
        let reg = RegressionData::new(
            header,
            Path::new("/nonexistent/path"),
            None,
            None,
            None,
            false,
        );
        assert!(!reg.exists());
    }

    #[test]
    fn test_add_alert() {
        let header = RegressionHeader::new("rule-id".into(), "Test".into());
        let mut reg = RegressionData::new(header, Path::new("/tmp"), None, None, None, false);
        let alert = sample_alert("test-rule", test_event_json());
        reg.add_alert(alert);
        assert_eq!(reg.alerts.len(), 1);
        assert_eq!(reg.alerts[0].channel(), "Security");
        assert_eq!(reg.alerts[0].record_id(), Some(42));
        assert_eq!(
            reg.alerts[0].provider(),
            "Microsoft-Windows-Security-Auditing"
        );
    }

    #[test]
    fn test_generate_with_mock_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let header = RegressionHeader::new("test-rule-uuid".into(), "Test Rule".into());
        let mut reg = RegressionData::new(
            header,
            tmp.path(),
            None,
            Some("Test Author"),
            Some("Test Description"),
            false,
        );
        reg.add_alert(sample_alert("test-rule-uuid", test_event_json()));

        let writer = MockWriter::new();
        reg.generate(&writer).unwrap();

        let rule_dir = tmp.path().join("rules").join("test-rule-uuid");
        assert!(rule_dir.join("test-rule-uuid.json").exists());
        assert!(rule_dir.join("test-rule-uuid.evtx").exists());
        assert!(rule_dir.join("info.yml").exists());
        assert_eq!(writer.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_generate_no_alerts() {
        let tmp = tempfile::tempdir().unwrap();
        let header = RegressionHeader::new("empty-rule".into(), "Empty".into());
        let reg = RegressionData::new(header, tmp.path(), None, None, None, false);

        let writer = MockWriter::new();
        reg.generate(&writer).unwrap();

        let rule_dir = tmp.path().join("rules").join("empty-rule");
        assert!(rule_dir.join("info.yml").exists());
        assert!(!rule_dir.join("empty-rule.json").exists());
        assert!(!rule_dir.join("empty-rule.evtx").exists());
        assert_eq!(writer.call_count.load(Ordering::SeqCst), 0);
    }
}
