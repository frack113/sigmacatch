// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Generate rsigma-eval pipeline YAML from SigmaHQ thor.yml logsource definitions.
//!
//! Fetches `thor.yml` from SigmaHQ master, extracts Windows logsource mappings
//! (category → EventID → service), and produces a pipeline YAML compatible
//! with `rsigma-eval` 0.18.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin pipeline_generator
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use anyhow::{Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// thor.yml logsource rewrite structure
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ThorRewrite {
    #[allow(dead_code)]
    product: Option<String>,
    service: Option<String>,
}

// ---------------------------------------------------------------------------
// Pipeline YAML structures
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
struct Pipeline {
    name: String,
    priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    vars: Option<serde_yaml::Value>,
    transformations: Vec<serde_yaml::Value>,
}

#[derive(Debug, serde::Serialize)]
struct TransformationItem {
    id: String,
    #[serde(rename = "type")]
    r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    conditions: Option<serde_yaml::Value>,
    #[serde(rename = "rule_conditions")]
    rule_conditions: Option<Vec<RuleCondition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct RuleCondition {
    #[serde(rename = "type")]
    cond_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

#[derive(Debug)]
struct CategoryEventID {
    category: String,
    event_id: u32,
    service: Option<String>,
}

// ---------------------------------------------------------------------------
// Fetch thor.yml
// ---------------------------------------------------------------------------

async fn fetch_thor(url: &str) -> Result<String> {
    let resp = reqwest::get(url)
        .await
        .context("failed to connect to SigmaHQ GitHub")?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "HTTP {}: {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("unknown")
        );
    }
    let body = resp.text().await.context("failed to read thor.yml body")?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Extract logsource entries
// ---------------------------------------------------------------------------

/// Extract all Windows logsource entries that have a category + EventID.
fn extract_windows_logsources(thor: &serde_yaml::Value) -> Result<Vec<CategoryEventID>> {
    let map = thor
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("thor.yml root is not a mapping"))?;

    let logsources = map
        .get("logsources")
        .ok_or_else(|| anyhow::anyhow!("no 'logsources' key in thor.yml"))?;

    let logsource_map = logsources
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("'logsources' is not a mapping"))?;

    let mut mappings = Vec::new();

    for (_key, entry) in logsource_map {
        let entry_map = match entry.as_mapping() {
            Some(m) => m,
            None => continue,
        };

        let category = match entry_map.get("category") {
            Some(v) => v.as_str().map(|s| s.to_string()),
            None => None,
        };

        let product = match entry_map.get("product") {
            Some(v) => v.as_str().map(|s| s.to_string()),
            None => None,
        };

        // Only process Windows logsources with a category
        if product.as_deref() != Some("windows") || category.is_none() {
            continue;
        }

        let rewrite = match entry_map.get("rewrite") {
            Some(v) => serde_yaml::from_value::<ThorRewrite>(v.clone()).ok(),
            None => None,
        };

        let rewrite = match rewrite {
            Some(r) => r,
            None => continue,
        };

        let event_ids = match entry_map.get("conditions") {
            Some(conds) => parse_event_ids(conds),
            None => Vec::new(),
        };

        if event_ids.is_empty() {
            continue;
        }

        for eid in event_ids {
            mappings.push(CategoryEventID {
                category: category.clone().unwrap(),
                event_id: eid,
                service: rewrite.service.clone(),
            });
        }
    }

    Ok(mappings)
}

// ---------------------------------------------------------------------------
// Tier 2: channel → service mapping (sources: entries)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SourceChannel {
    service: String,
    channels: Vec<String>,
}

/// Extract all Windows logsource entries that use `sources:` (ETW channels)
/// instead of category + rewrite + conditions.
fn extract_source_channels(thor: &serde_yaml::Value) -> Result<Vec<SourceChannel>> {
    let map = thor
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("thor.yml root is not a mapping"))?;

    let logsources = map
        .get("logsources")
        .ok_or_else(|| anyhow::anyhow!("no 'logsources' key in thor.yml"))?;

    let logsource_map = logsources
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("'logsources' is not a mapping"))?;

    let mut by_service: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (_key, entry) in logsource_map {
        let entry_map = match entry.as_mapping() {
            Some(m) => m,
            None => continue,
        };

        let product = match entry_map.get("product") {
            Some(v) => v.as_str().map(|s| s.to_string()),
            None => None,
        };

        if product.as_deref() != Some("windows") {
            continue;
        }

        let service = match entry_map.get("service") {
            Some(v) => match v.as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            },
            None => continue,
        };

        let channels = match entry_map.get("sources") {
            Some(srcs) => parse_channels(srcs),
            None => Vec::new(),
        };

        if channels.is_empty() {
            continue;
        }

        by_service
            .entry(service)
            .or_default()
            .extend(channels);
    }

    Ok(by_service
        .into_iter()
        .map(|(service, mut channels)| {
            channels.sort();
            channels.dedup();
            SourceChannel { service, channels }
        })
        .collect())
}

fn parse_event_ids(value: &serde_yaml::Value) -> Vec<u32> {
    match value {
        // {"EventID": 12} → extract EventID
        serde_yaml::Value::Mapping(m) => {
            if let Some(event_val) = m.get(serde_yaml::Value::from("EventID")) {
                parse_single_event_id(event_val)
            } else {
                Vec::new()
            }
        }
        // Single number: EventID: 1
        serde_yaml::Value::Number(n) => n.as_u64().map(|nu| vec![nu as u32]).unwrap_or_default(),
        // Direct sequence: EventID: [1, 2]
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| match v {
                serde_yaml::Value::Number(n) => n.as_u64().map(|nu| nu as u32),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_single_event_id(value: &serde_yaml::Value) -> Vec<u32> {
    match value {
        serde_yaml::Value::Number(n) => n.as_u64().map(|nu| vec![nu as u32]).unwrap_or_default(),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| match v {
                serde_yaml::Value::Number(n) => n.as_u64().map(|nu| nu as u32),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse channel names from a `sources:` field in thor.yml.
fn parse_channels(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Mapping(m) => m
            .iter()
            .filter_map(|(k, _v)| k.as_str().map(|s| s.to_string()))
            .collect(),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| match v {
                serde_yaml::Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Build pipeline transformations
// ---------------------------------------------------------------------------

fn dedup_category_eventids(raw: Vec<CategoryEventID>) -> Vec<CategoryEventID> {
    let mut seen: BTreeSet<(String, u32)> = BTreeSet::new();
    raw.into_iter()
        .filter(|c| seen.insert((c.category.clone(), c.event_id)))
        .collect()
}

fn build_add_condition_transformations(mappings: &[CategoryEventID]) -> Vec<TransformationItem> {
    let mut cat_eid_service: BTreeMap<(String, u32), String> = BTreeMap::new();
    for m in mappings {
        cat_eid_service
            .entry((m.category.clone(), m.event_id))
            .or_insert_with(|| m.service.clone().unwrap_or_default());
    }

    cat_eid_service
        .into_iter()
        .map(|((category, event_id), service)| {
            let conditions_value = {
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::from("EventID"),
                    serde_yaml::Value::from(event_id),
                );
                serde_yaml::Value::from(map)
            };
            TransformationItem {
                id: format!("evt_{}_{}", category, event_id),
                r#type: "add_condition".to_string(),
                conditions: Some(conditions_value),
                rule_conditions: Some(vec![RuleCondition {
                    cond_type: "logsource".to_string(),
                    category: Some(category),
                    product: Some("windows".to_string()),
                    service: Some(service),
                }]),
                product: None,
                service: None,
            }
        })
        .collect()
}

fn build_change_logsource_transformations() -> Vec<TransformationItem> {
    // Final catch-all: Windows → sysmon
    vec![TransformationItem {
        id: "sysmon_logsource".to_string(),
        r#type: "change_logsource".to_string(),
        conditions: None,
        rule_conditions: Some(vec![RuleCondition {
            cond_type: "logsource".to_string(),
            category: None,
            product: Some("windows".to_string()),
            service: None,
        }]),
        product: Some("windows".to_string()),
        service: Some("sysmon".to_string()),
    }]
}

// ---------------------------------------------------------------------------
// Write pipeline
// ---------------------------------------------------------------------------

fn write_pipeline(pipeline: &Pipeline, output: &str) -> Result<()> {
    let content = serde_yaml::to_string(pipeline).context("failed to serialize pipeline")?;
    fs::write(output, content).context("failed to write pipeline YAML")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const DEFAULT_OUTPUT: &str = "pipelines/sysmon.yml";
const CHANNEL_MAPPING_OUTPUT: &str = "pipelines/channel_mapping.yml";
const THOR_URL: &str =
    "https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/tests/thor.yml";

#[tokio::main]
async fn main() -> Result<()> {
    let output = DEFAULT_OUTPUT;
    let channel_mapping_output = CHANNEL_MAPPING_OUTPUT;
    let thor_content = fetch_thor(THOR_URL).await?;

    let thor: serde_yaml::Value =
        serde_yaml::from_str(&thor_content).context("failed to parse thor.yml")?;

    // Tier 1: category + rewrite + conditions → pipeline YAML
    let raw_mappings = extract_windows_logsources(&thor)?;

    if raw_mappings.is_empty() {
        eprintln!("No Windows logsource mappings found in thor.yml");
        std::process::exit(1);
    }

    println!(
        "Tier 1: Found {} raw Windows logsource mappings",
        raw_mappings.len()
    );

    // Dedup by (category, event_id)
    let mappings = dedup_category_eventids(raw_mappings);
    println!(
        "Tier 1: Deduplicated to {} unique (category, EventID) pairs",
        mappings.len()
    );

    // Show summary
    let mut services = BTreeSet::new();
    for m in &mappings {
        if let Some(ref svc) = m.service {
            services.insert(svc.clone());
        }
    }
    println!("Tier 1: Services: {}", services.len());
    for svc in &services {
        println!("  - {svc}");
    }

    // Tier 2: sources: → channel mapping
    let source_channels = extract_source_channels(&thor)?;
    let mut total_channels: usize = 0;
    for sc in &source_channels {
        total_channels += sc.channels.len();
    }
    println!("Tier 2: Found {} service → channel mappings", source_channels.len());
    println!("Tier 2: Total unique channels: {}", total_channels);

    // Write Tier 1
    generate_and_write(&mappings, output)?;

    // Write Tier 2
    write_channel_mapping(&source_channels, channel_mapping_output)?;

    Ok(())
}

fn generate_and_write(mappings: &[CategoryEventID], output: &str) -> Result<()> {
    let add_condition = build_add_condition_transformations(mappings);
    let change_logsource = build_change_logsource_transformations();

    // Flatten: Vec<TransformationItem> → Vec<serde_yaml::Value>
    let all_transformations: Vec<TransformationItem> =
        add_condition.into_iter().chain(change_logsource).collect();

    let pipeline = Pipeline {
        name: "sigmacatch-windows".to_string(),
        priority: 10,
        vars: None,
        transformations: all_transformations
            .into_iter()
            .map(|t| serde_yaml::to_value(&t).context("failed to serialize transformation"))
            .collect::<Result<Vec<_>>>()?,
    };

    // Ensure output directory exists
    if let Some(parent) = std::path::Path::new(output).parent() {
        fs::create_dir_all(parent)?;
    }

    write_pipeline(&pipeline, output)?;
    println!("Pipeline written to {}", output);

    Ok(())
}

/// Build channel_to_service map from service → channels, then reverse it.
fn build_channel_to_service(source_channels: &[SourceChannel]) -> BTreeMap<String, String> {
    let mut channel_to_service: BTreeMap<String, String> = BTreeMap::new();
    for sc in source_channels {
        for channel in &sc.channels {
            channel_to_service.insert(channel.clone(), sc.service.clone());
        }
    }
    channel_to_service
}

fn write_channel_mapping(source_channels: &[SourceChannel], output: &str) -> Result<()> {
    let channel_to_service = build_channel_to_service(source_channels);
    let channel_to_service_val = serde_yaml::to_value(&channel_to_service)
        .context("failed to convert channel_to_service to YAML value")?;
    let mut out_map = serde_yaml::Mapping::new();
    out_map.insert(
        serde_yaml::Value::from("channel_to_service"),
        channel_to_service_val,
    );

    let content = serde_yaml::to_string(&serde_yaml::Value::from(out_map))
        .context("failed to serialize channel mapping to YAML")?;

    fs::write(output, content).context("failed to write channel mapping YAML")?;
    println!("Channel mapping written to {}", output);

    Ok(())
}
