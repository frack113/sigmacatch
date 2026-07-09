use anyhow::{Context, Result};
use rsigma_eval::result::RuleHeader;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::regression::info_yml::InfoYml;

pub struct MatchEvent {
    pub event: Value,
    pub raw_xml: String,
}

pub struct RegressionData {
    pub header: RuleHeader,
    pub events: Vec<MatchEvent>,
    pub output_path: PathBuf,
    pub rule_rel_path: Option<PathBuf>,
    pub author: Option<String>,
}

impl RegressionData {
    pub fn new(
        header: RuleHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
    ) -> Self {
        Self {
            header,
            events: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
        }
    }

    pub fn add_event(&mut self, event: Value, raw_xml: String) {
        self.events.push(MatchEvent { event, raw_xml });
    }

    pub fn rule_dir(&self) -> Result<PathBuf> {
        if let Some(rel_path) = &self.rule_rel_path {
            return Ok(self.output_path.join(rel_path));
        }
        let rule_id = self.header.rule_id.as_deref().unwrap_or("unknown");
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
        self.rule_rel_path.as_ref().and_then(|rel_path| {
            Some(format!(
                "{}/{}",
                self.output_path.file_name()?.to_string_lossy(),
                rel_path.display()
            ))
        })
    }

    pub fn exists(&self) -> bool {
        self.rule_dir().is_ok_and(|d| d.join("info.yml").exists())
    }

    pub fn generate(&self) -> Result<()> {
        let rule_dir = self.rule_dir()?;
        let rule_id = self.header.rule_id.as_deref().unwrap_or("unknown");
        std::fs::create_dir_all(&rule_dir)
            .with_context(|| format!("Failed to create rule directory {:?}", rule_dir))?;

        let first = self.events.first();
        let match_count = if first.is_some() { 1 } else { 0 };

        if let Some(event) = first {
            let raw_json_path = rule_dir.join(format!("{}.json", rule_id));
            let raw_json = serde_json::to_string_pretty(&event.event)?;
            std::fs::write(&raw_json_path, raw_json)?;
            info!("Wrote JSON for rule {:?}", rule_id);

            let evtx_path = rule_dir.join(format!("{}.evtx", rule_id));
            crate::evtx::writer::write_evtx(&event.raw_xml, &evtx_path)
                .with_context(|| format!("Failed to write EVTX for rule {:?}", rule_id))?;
            info!("Wrote EVTX for rule {:?}", rule_id);
        }

        let sigma_evtx_path = if first.is_some() {
            let evtx_name = format!("{}.evtx", rule_id);
            rule_dir
                .join(&evtx_name)
                .strip_prefix(&self.output_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| evtx_name)
        } else {
            String::new()
        };

        let author = self
            .author
            .as_deref()
            .unwrap_or("Sigma Regression Generator");

        let info = InfoYml::new(
            rule_id,
            &self.header.rule_title,
            match_count,
            &sigma_evtx_path,
            author,
        );
        let info_path = rule_dir.join("info.yml");
        info.save(&info_path)?;
        info!("Created info.yml at {:?}", info_path);

        info!(
            "Generated {} regression events for rule {:?}",
            self.events.len(),
            self.header.rule_id
        );
        Ok(())
    }
}
