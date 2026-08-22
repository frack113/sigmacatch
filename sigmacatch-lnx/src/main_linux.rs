// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::DataFormat;
use sigmacatch_runner::{self, CollectorKind};
use sigmacatch_types::EventProducer;

use sigmacatch_lnx::{auditd, syslog};

struct LinuxCollector;

impl CollectorKind for LinuxCollector {
    fn name(&self) -> &'static str {
        "sigmacatch-linux"
    }

    fn mode(&self) -> &'static str {
        if std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file() {
            "linux auditd"
        } else {
            "linux syslog"
        }
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        if std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file() {
            Box::new(auditd::EventCollector::new())
        } else {
            Box::new(syslog::EventCollector::new())
        }
    }

    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
}

#[cfg(feature = "tools")]
mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    if !std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file()
        && syslog::discover_default_path().is_none()
    {
        anyhow::bail!(
            "no linux log source found: {} (auditd) nor {:?} (central syslog). \
             Install/configure one of them first.",
            auditd::DEFAULT_LOG_PATH,
            syslog::DEFAULT_LOG_PATHS,
        );
    }
    #[cfg(feature = "tools")]
    {
        let code = cli::dispatch();
        if code != 0 {
            std::process::exit(code);
        }
    }
    sigmacatch_runner::run(&LinuxCollector).await
}
