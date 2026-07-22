// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use rsigma_parser::LogSource;
use serde_json::Value;
use std::path::PathBuf;

pub use win_evt_core::types::WinevtEvent;

#[derive(Debug, Clone)]
pub struct Alert {
    pub rule_id: String,
    pub header: rsigma_eval::result::RuleHeader,
    pub event: Value,
    pub raw_xml: String,
    pub channel: String,
    pub provider: String,
    pub record_id: Option<u64>,
}

pub trait Collector {
    fn collect(&self, channels: &[String]) -> Result<Vec<WinevtEvent>>;
}

pub trait Evaluator {
    fn evaluate(&self, event: &WinevtEvent, logsource: &LogSource) -> Vec<Alert>;
}

pub trait Generator {
    type Config;

    fn generate(&self, alerts: &[Alert], config: &Self::Config) -> Result<()>;
}

// ─── Real implementations ─────────────────────────────────────────────

/// Sync wrapper around the existing WinevtCollector.
/// On non-Windows, returns empty events.
#[derive(Default)]
pub struct EventLogCollector;

impl Collector for EventLogCollector {
    fn collect(&self, channels: &[String]) -> Result<Vec<WinevtEvent>> {
        #[cfg(not(windows))]
        {
            let _ = channels;
            use tracing::info;
            info!("EventLogCollector: non-Windows platform, returning empty events");
            Ok(Vec::new())
        }

        #[cfg(windows)]
        {
            let mut all_events = Vec::new();
            for channel in channels {
                let raw_events = crate::collectors::event_log::collect_events(channel)?;
                for evt in raw_events {
                    all_events.push(WinevtEvent {
                        channel: evt.channel,
                        event_id: evt.event_id,
                        raw_xml: evt.raw_xml,
                        event_json: evt.event_json,
                    });
                }
            }
            Ok(all_events)
        }
    }
}

/// Wraps SigmaEngine to implement the Evaluator trait.
pub struct SigmaEvaluator<'a> {
    engine: &'a crate::sigma::engine::SigmaEngine,
}

impl<'a> SigmaEvaluator<'a> {
    pub fn new(engine: &'a crate::sigma::engine::SigmaEngine) -> Self {
        Self { engine }
    }
}

impl Evaluator for SigmaEvaluator<'_> {
    fn evaluate(&self, event: &WinevtEvent, logsource: &LogSource) -> Vec<Alert> {
        let event_json = match &event.event_json {
            Some(j) => j,
            None => return Vec::new(),
        };
        let results = self
            .engine
            .evaluate_event_with_logsource(event_json, logsource);
        results
            .into_iter()
            .map(|r| {
                let rule_id = r
                    .header
                    .rule_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                Alert {
                    rule_id,
                    header: r.header,
                    event: event_json.clone(),
                    raw_xml: event.raw_xml.clone(),
                    channel: event.channel.clone(),
                    provider: event_json
                        .get("ProviderName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    record_id: event_json.get("EventRecordID_num").and_then(|v| v.as_u64()),
                }
            })
            .collect()
    }
}

/// Configuration for the RegressionGenerator.
pub struct GeneratorConfig {
    pub output_path: PathBuf,
    pub author: String,
    pub is_contrib: bool,
    pub skip_set: std::collections::HashSet<String>,
    pub engine: crate::sigma::engine::SigmaEngine,
    pub retired: std::collections::HashSet<String>,
}

/// Groups alerts by rule_id and generates regression data for each.
pub struct RegressionGenerator;

impl Generator for RegressionGenerator {
    type Config = GeneratorConfig;

    fn generate(&self, alerts: &[Alert], config: &Self::Config) -> Result<()> {
        use crate::regression::generator::RegressionData;
        use std::collections::HashMap;

        let mut grouped: HashMap<String, Vec<&Alert>> = HashMap::new();
        for alert in alerts {
            if config.retired.contains(&alert.rule_id) {
                continue;
            }
            grouped
                .entry(alert.rule_id.clone())
                .or_default()
                .push(alert);
        }

        for (rule_id, alerts) in &grouped {
            if config.skip_set.contains(rule_id) {
                continue;
            }

            let first = &alerts[0];
            let rule_path = config.engine.rule_path(rule_id).cloned();
            let rule_rel_path = rule_path.as_ref().and_then(|p| {
                p.strip_prefix("sigma")
                    .ok()
                    .map(|rel| rel.with_extension(""))
            });
            let description = config
                .engine
                .rule_description(rule_id)
                .map(|s| s.to_string());

            let mut reg = RegressionData::new(
                first.header.clone(),
                &config.output_path,
                rule_rel_path.as_deref(),
                Some(&config.author),
                description.as_deref(),
                config.is_contrib,
            );

            if reg.exists() {
                continue;
            }

            for alert in alerts {
                reg.add_event(
                    alert.event.clone(),
                    alert.raw_xml.clone(),
                    alert.channel.clone(),
                    alert.record_id,
                    alert.provider.clone(),
                );
            }

            reg.generate()?;
        }

        Ok(())
    }
}

// ─── Pipeline orchestrator ────────────────────────────────────────────

pub struct Pipeline<C: Collector, E: Evaluator, G: Generator> {
    collector: C,
    evaluator: E,
    generator: G,
}

impl<C: Collector, E: Evaluator, G: Generator> Pipeline<C, E, G> {
    pub fn new(collector: C, evaluator: E, generator: G) -> Self {
        Self {
            collector,
            evaluator,
            generator,
        }
    }

    pub fn run(
        &self,
        channels: &[String],
        logsource: &LogSource,
        gen_config: &G::Config,
    ) -> Result<PipelineStats> {
        let events = self.collector.collect(channels)?;
        let mut all_alerts = Vec::new();
        for event in &events {
            let alerts = self.evaluator.evaluate(event, logsource);
            all_alerts.extend(alerts);
        }
        self.generator.generate(&all_alerts, gen_config)?;
        Ok(PipelineStats {
            events_processed: events.len(),
            alerts_generated: all_alerts.len(),
        })
    }
}

pub struct PipelineStats {
    pub events_processed: usize,
    pub alerts_generated: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct MockCollector {
        events: Vec<WinevtEvent>,
    }

    impl Collector for MockCollector {
        #[cfg_attr(not(windows), allow(unused_variables))]
        fn collect(&self, channels: &[String]) -> Result<Vec<WinevtEvent>> {
            Ok(self.events.clone())
        }
    }

    struct MockEvaluator {
        alert_count: RefCell<usize>,
    }

    impl Evaluator for MockEvaluator {
        fn evaluate(&self, event: &WinevtEvent, _logsource: &LogSource) -> Vec<Alert> {
            if event.event_id == 1 {
                *self.alert_count.borrow_mut() += 1;
                vec![Alert {
                    rule_id: "test-rule-1".to_string(),
                    header: rsigma_eval::result::RuleHeader {
                        rule_title: "Test Rule".to_string(),
                        rule_id: Some("test-rule-1".to_string()),
                        level: None,
                        tags: Vec::new(),
                        custom_attributes: Arc::new(HashMap::new()),
                        enrichments: None,
                    },
                    event: serde_json::json!({"EventID": 1}),
                    raw_xml: String::new(),
                    channel: "Security".to_string(),
                    provider: "Microsoft-Windows-Security-Auditing".to_string(),
                    record_id: None,
                }]
            } else {
                Vec::new()
            }
        }
    }

    #[derive(Default)]
    struct MockGeneratorConfig;

    struct MockGenerator {
        generated: RefCell<Vec<String>>,
    }

    impl Generator for MockGenerator {
        type Config = MockGeneratorConfig;

        fn generate(&self, alerts: &[Alert], _config: &MockGeneratorConfig) -> Result<()> {
            for alert in alerts {
                self.generated.borrow_mut().push(alert.rule_id.clone());
            }
            Ok(())
        }
    }

    fn test_logsource() -> LogSource {
        LogSource {
            product: Some("windows".into()),
            service: Some("sysmon".into()),
            category: None,
            definition: None,
            custom: HashMap::new(),
        }
    }

    #[test]
    fn test_pipeline_sequential() {
        let collector = MockCollector {
            events: vec![
                WinevtEvent {
                    channel: "Security".to_string(),
                    event_id: 1,
                    raw_xml: "<Event>...</Event>".to_string(),
                    event_json: Some(serde_json::json!({"EventID": 1})),
                },
                WinevtEvent {
                    channel: "Security".to_string(),
                    event_id: 2,
                    raw_xml: "<Event>...</Event>".to_string(),
                    event_json: Some(serde_json::json!({"EventID": 2})),
                },
            ],
        };

        let evaluator = MockEvaluator {
            alert_count: RefCell::new(0),
        };

        let generator = MockGenerator {
            generated: RefCell::new(Vec::new()),
        };

        let pipeline = Pipeline::new(collector, evaluator, generator);
        let stats = pipeline
            .run(
                &["Security".to_string()],
                &test_logsource(),
                &MockGeneratorConfig,
            )
            .unwrap();

        assert_eq!(stats.events_processed, 2);
        assert_eq!(stats.alerts_generated, 1);
    }

    #[test]
    fn test_collector_isolation() {
        let collector = MockCollector {
            events: vec![WinevtEvent {
                channel: "System".to_string(),
                event_id: 42,
                raw_xml: String::new(),
                event_json: None,
            }],
        };

        let events = collector.collect(&["System".to_string()]).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 42);
    }

    #[test]
    fn test_evaluator_isolation() {
        let evaluator = MockEvaluator {
            alert_count: RefCell::new(0),
        };

        let event = WinevtEvent {
            channel: "Security".to_string(),
            event_id: 1,
            raw_xml: String::new(),
            event_json: Some(serde_json::json!({"EventID": 1})),
        };

        let alerts = evaluator.evaluate(&event, &test_logsource());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "test-rule-1");
    }

    #[test]
    fn test_generator_isolation() {
        let generator = MockGenerator {
            generated: RefCell::new(Vec::new()),
        };

        let alerts = vec![Alert {
            rule_id: "test-rule-1".to_string(),
            header: rsigma_eval::result::RuleHeader {
                rule_title: "Test Rule".to_string(),
                rule_id: Some("test-rule-1".to_string()),
                level: None,
                tags: Vec::new(),
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            event: serde_json::json!({}),
            raw_xml: String::new(),
            channel: "Security".to_string(),
            provider: String::new(),
            record_id: None,
        }];

        generator.generate(&alerts, &MockGeneratorConfig).unwrap();
        assert_eq!(generator.generated.borrow().len(), 1);
    }
}
