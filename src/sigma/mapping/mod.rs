// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

pub mod channel_mapping;
pub mod custom;
pub mod taxonomy;

use channel_mapping::CHANNEL_TO_SERVICE_MAP;
use rsigma_parser::LogSource;
use std::collections::HashMap;
use taxonomy::{CHANNEL_EVENT_TO_CATEGORY, CHANNEL_EVENT_TO_SUBCATEGORY, PROVIDER_TO_SERVICE};
use tracing::debug;

/// Resolve LogSource from channel, provider, and event_id.
///
/// INVARIANT: channel > provider > default
/// Priority order MUST NOT be changed:
///   1. Channel → service (CHANNEL_TO_SERVICE_MAP + custom_map override)
///   2. Provider → service (PROVIDER_TO_SERVICE) fallback
///   3. Default: product=windows, service=None, category=None
///
/// This invariant is documented in AGENTS.md and architecture-reference.md.
pub fn resolve_logsource(
    channel: &str,
    provider: &str,
    event_id: u32,
    custom_map: &HashMap<String, String>,
) -> LogSource {
    // 1. Custom override (highest priority)
    if let Some(service) = custom_map.get(channel) {
        debug!(
            "LogSource resolved via custom_map: service={}, category={:?}",
            service,
            get_category(channel, event_id)
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.clone()),
            category: get_category(channel, event_id).map(|s| s.to_string()),
            ..LogSource::default()
        };
    }

    // 2. Channel → service from YAML mapping
    if let Some(service) = CHANNEL_TO_SERVICE_MAP.get(channel) {
        let category = get_category(channel, event_id);
        debug!(
            "LogSource resolved via channel: service={}, category={:?}",
            service, category
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.to_string()),
            category: category.map(|s| s.to_string()),
            ..LogSource::default()
        };
    }

    // 3. Provider → service fallback
    if let Some(service) = PROVIDER_TO_SERVICE.get(provider) {
        debug!(
            "LogSource resolved via provider fallback: service={}",
            service
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.to_string()),
            category: None,
            ..LogSource::default()
        };
    }

    debug!("LogSource resolved via default: product=windows");
    LogSource {
        product: Some("windows".into()),
        service: None,
        category: None,
        ..LogSource::default()
    }
}

/// Extract category from channel + event_id using static category maps.
fn get_category(channel: &str, event_id: u32) -> Option<&'static str> {
    let composite_key = format!("{}:{}", channel, event_id);
    CHANNEL_EVENT_TO_SUBCATEGORY
        .get(&composite_key)
        .copied()
        .or_else(|| CHANNEL_EVENT_TO_CATEGORY.get(&composite_key).copied())
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChannelTarget {
    pub channel: String,
    pub event_ids: Option<Vec<u32>>,
}

/// Build a reverse map: service (or service:category) → Vec<ChannelTarget>.
///
/// Sources (in priority):
/// 1. Custom map → custom service keys
/// 2. CHANNEL_TO_SERVICE_MAP (YAML) → service keys
/// 3. CHANNEL_EVENT_TO_CATEGORY (static) → service:category keys
#[allow(dead_code)]
pub fn build_logsource_to_channels(
    custom_map: &HashMap<String, String>,
) -> HashMap<String, Vec<ChannelTarget>> {
    let mut service_targets: HashMap<String, Vec<String>> = HashMap::new();
    let mut category_targets: HashMap<String, Vec<(String, Vec<u32>)>> = HashMap::new();

    // Build service-level keys from YAML (primary source)
    for (channel, service) in &*CHANNEL_TO_SERVICE_MAP {
        service_targets
            .entry(service.clone())
            .or_default()
            .push(channel.clone());
    }

    // Add custom channels to service-level keys (lowest priority)
    for (channel, service) in custom_map {
        service_targets
            .entry(service.clone())
            .or_default()
            .push(channel.clone());
    }

    // Build category-level keys from CHANNEL_EVENT_TO_CATEGORY
    for (key, category) in &CHANNEL_EVENT_TO_CATEGORY {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE_MAP.get(channel) {
                    let cat_key = format!("{}:{}", service, category);
                    category_targets
                        .entry(cat_key)
                        .or_default()
                        .push((channel.to_string(), vec![eid]));
                }
            }
        }
    }

    // Add subcategory events to parent category (subcategory is a refinement, not a replacement)
    for (key, subcat) in &CHANNEL_EVENT_TO_SUBCATEGORY {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE_MAP.get(channel) {
                    let subcat_key = format!("{}:{}", service, subcat);
                    let parent_key = format!(
                        "{}:{}",
                        service,
                        CHANNEL_EVENT_TO_CATEGORY
                            .get(key)
                            .copied()
                            .unwrap_or_default()
                    );
                    category_targets
                        .entry(subcat_key)
                        .or_default()
                        .push((channel.to_string(), vec![eid]));
                    if let Some(parent_targets) = category_targets.get_mut(&parent_key) {
                        parent_targets.push((channel.to_string(), vec![eid]));
                    }
                }
            }
        }
    }

    // Convert to final format, merging service + category targets
    let mut merged: HashMap<String, Vec<ChannelTarget>> = HashMap::new();

    for (service, channels) in service_targets {
        let mut targets: Vec<ChannelTarget> = channels
            .into_iter()
            .map(|channel| ChannelTarget {
                channel,
                event_ids: None,
            })
            .collect();
        targets.sort_by(|a, b| a.channel.cmp(&b.channel));
        merged.insert(service, targets);
    }

    for (cat_key, targets) in category_targets {
        let existing: Vec<ChannelTarget> = merged.remove(&cat_key).unwrap_or_default();
        let mut by_channel: HashMap<String, Vec<u32>> = HashMap::new();
        for (channel, eids) in targets {
            by_channel.entry(channel).or_default().extend(eids);
        }
        let mut merged_targets: Vec<ChannelTarget> = by_channel
            .into_iter()
            .map(|(channel, mut eids)| {
                eids.sort();
                eids.dedup();
                ChannelTarget {
                    channel,
                    event_ids: Some(eids),
                }
            })
            .collect();
        merged_targets.extend(existing);
        merged_targets.sort_by(|a, b| a.channel.cmp(&b.channel));
        merged.insert(cat_key, merged_targets);
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_channel_known() {
        let ls = resolve_logsource(
            "Microsoft-Windows-Sysmon/Operational",
            "",
            1,
            &HashMap::new(),
        );
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service.as_deref(), Some("sysmon"));
        assert_eq!(ls.category.as_deref(), Some("process_creation"));
    }

    #[test]
    fn test_resolve_channel_unknown_provider_fallback() {
        let ls = resolve_logsource("", "Microsoft-Windows-Sysmon", 1, &HashMap::new());
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service.as_deref(), Some("sysmon"));
    }

    #[test]
    fn test_resolve_both_unknown() {
        let ls = resolve_logsource("UnknownChannel", "UnknownProvider", 0, &HashMap::new());
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service, None);
        assert_eq!(ls.category, None);
    }

    #[test]
    fn test_build_sysmon_service_level() {
        let map = build_logsource_to_channels(&HashMap::new());
        let sysmon = map.get("sysmon").expect("sysmon entry exists");
        assert!(sysmon
            .iter()
            .any(|t| t.channel == "Microsoft-Windows-Sysmon/Operational"));
        assert!(sysmon.iter().all(|t| t.event_ids.is_none()));
    }

    #[test]
    fn test_build_sysmon_process_creation() {
        let map = build_logsource_to_channels(&HashMap::new());
        let targets = map
            .get("sysmon:process_creation")
            .expect("sysmon:process_creation entry exists");
        let t = targets
            .iter()
            .find(|t| t.channel == "Microsoft-Windows-Sysmon/Operational")
            .unwrap();
        assert_eq!(t.event_ids.as_deref(), Some(&[1u32][..]));
    }

    #[test]
    fn test_build_applocker_multiple_channels() {
        let map = build_logsource_to_channels(&HashMap::new());
        let applocker = map.get("applocker").expect("applocker entry exists");
        assert!(
            applocker.len() >= 4,
            "expected >=4 applocker channels, got {}",
            applocker.len()
        );
        let names: Vec<String> = applocker.iter().map(|t| t.channel.clone()).collect();
        assert!(names.contains(&"Microsoft-Windows-AppLocker/EXE and DLL".to_string()));
        assert!(names.contains(&"Microsoft-Windows-AppLocker/MSI and Script".to_string()));
        assert!(names.contains(&"Microsoft-Windows-AppLocker/Packaged app-Deployment".to_string()));
        assert!(names.contains(&"Microsoft-Windows-AppLocker/Packaged app-Execution".to_string()));
    }

    #[test]
    fn test_build_security_login() {
        let map = build_logsource_to_channels(&HashMap::new());
        let targets = map
            .get("security:login")
            .expect("security:login entry exists");
        let t = targets.iter().find(|t| t.channel == "Security").unwrap();
        assert_eq!(t.event_ids.as_deref(), Some(&[4624u32][..]));
    }

    #[test]
    fn test_build_powershell_ps_script() {
        let map = build_logsource_to_channels(&HashMap::new());
        let targets = map
            .get("powershell:ps_script")
            .expect("powershell:ps_script entry exists");
        let t = targets
            .iter()
            .find(|t| t.channel == "Microsoft-Windows-PowerShell/Operational")
            .unwrap();
        assert_eq!(t.event_ids.as_deref(), Some(&[4104u32][..]));
    }

    #[test]
    fn test_build_unknown_key() {
        let map = build_logsource_to_channels(&HashMap::new());
        assert!(map.get("nonexistent:category").is_none());
    }

    #[test]
    fn test_build_registry_event_merged() {
        let map = build_logsource_to_channels(&HashMap::new());
        let targets = map
            .get("sysmon:registry_event")
            .expect("sysmon:registry_event entry exists");
        let t = targets
            .iter()
            .find(|t| t.channel == "Microsoft-Windows-Sysmon/Operational")
            .unwrap();
        let eids = t.event_ids.as_deref().unwrap();
        assert!(eids.contains(&12));
        assert!(eids.contains(&13));
        assert!(eids.contains(&14));
    }

    #[test]
    fn test_resolve_logsource_with_custom_override() {
        let mut custom = HashMap::new();
        custom.insert("Security".to_string(), "custom_security".to_string());
        let ls = resolve_logsource("Security", "", 4624, &custom);
        assert_eq!(ls.service.as_deref(), Some("custom_security"));
    }

    #[test]
    fn test_resolve_logsource_custom_fallback_to_static() {
        let custom = HashMap::new();
        let ls = resolve_logsource("Microsoft-Windows-Sysmon/Operational", "", 1, &custom);
        assert_eq!(ls.service.as_deref(), Some("sysmon"));
    }

    #[test]
    fn test_build_logsource_to_channels_with_custom() {
        let mut custom = HashMap::new();
        custom.insert(
            "Custom-Channel/Operational".to_string(),
            "custom_service".to_string(),
        );
        let map = build_logsource_to_channels(&custom);
        assert!(map.contains_key("custom_service"));
        let targets = map.get("custom_service").unwrap();
        assert!(targets
            .iter()
            .any(|t| t.channel == "Custom-Channel/Operational"));
    }

    #[test]
    fn test_resolve_logsource_custom_category() {
        let custom = HashMap::new();
        let ls = resolve_logsource("Security", "", 4624, &custom);
        assert_eq!(ls.category.as_deref(), Some("login"));
    }

    #[test]
    fn test_resolve_logsource_provider_fallback_no_custom() {
        let custom = HashMap::new();
        let ls = resolve_logsource("UnknownChannel", "Microsoft-Windows-Sysmon", 1, &custom);
        assert_eq!(ls.service.as_deref(), Some("sysmon"));
        assert_eq!(ls.category, None);
    }

    // ─── Sysmon category resolution tests (per spec v2.1.0) ────────────
    macro_rules! sysmon_category_test {
        ($name:ident, $eid:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let ls = resolve_logsource(
                    "Microsoft-Windows-Sysmon/Operational",
                    "",
                    $eid,
                    &HashMap::new(),
                );
                assert_eq!(ls.product.as_deref(), Some("windows"));
                assert_eq!(ls.service.as_deref(), Some("sysmon"));
                assert_eq!(ls.category.as_deref(), Some($expected));
            }
        };
    }

    sysmon_category_test!(test_sysmon_2_file_change, 2, "file_change");
    sysmon_category_test!(test_sysmon_3_network_connection, 3, "network_connection");
    sysmon_category_test!(test_sysmon_4_sysmon_status, 4, "sysmon_status");
    sysmon_category_test!(test_sysmon_5_process_termination, 5, "process_termination");
    sysmon_category_test!(test_sysmon_6_driver_load, 6, "driver_load");
    sysmon_category_test!(test_sysmon_7_image_load, 7, "image_load");
    sysmon_category_test!(
        test_sysmon_8_create_remote_thread,
        8,
        "create_remote_thread"
    );
    sysmon_category_test!(test_sysmon_9_raw_access_thread, 9, "raw_access_thread");
    sysmon_category_test!(test_sysmon_10_process_access, 10, "process_access");
    sysmon_category_test!(test_sysmon_11_file_event, 11, "file_event");
    sysmon_category_test!(test_sysmon_12_registry_add, 12, "registry_add");
    sysmon_category_test!(test_sysmon_13_registry_set, 13, "registry_set");
    sysmon_category_test!(test_sysmon_14_registry_rename, 14, "registry_rename");
    sysmon_category_test!(test_sysmon_15_create_stream_hash, 15, "create_stream_hash");
    sysmon_category_test!(test_sysmon_16_sysmon_status, 16, "sysmon_status");
    sysmon_category_test!(test_sysmon_17_pipe_created, 17, "pipe_created");
    sysmon_category_test!(test_sysmon_18_pipe_created, 18, "pipe_created");
    sysmon_category_test!(test_sysmon_19_wmi_event, 19, "wmi_event");
    sysmon_category_test!(test_sysmon_20_wmi_event, 20, "wmi_event");
    sysmon_category_test!(test_sysmon_21_wmi_event, 21, "wmi_event");
    sysmon_category_test!(test_sysmon_22_dns_query, 22, "dns_query");
    sysmon_category_test!(test_sysmon_23_file_delete, 23, "file_delete");
    sysmon_category_test!(test_sysmon_24_clipboard_capture, 24, "clipboard_capture");
    sysmon_category_test!(test_sysmon_25_process_tampering, 25, "process_tampering");
    sysmon_category_test!(
        test_sysmon_26_file_delete_detected,
        26,
        "file_delete_detected"
    );
    sysmon_category_test!(
        test_sysmon_27_file_block_executable,
        27,
        "file_block_executable"
    );
    sysmon_category_test!(
        test_sysmon_28_file_block_shredding,
        28,
        "file_block_shredding"
    );
    sysmon_category_test!(
        test_sysmon_29_file_executable_detected,
        29,
        "file_executable_detected"
    );
    sysmon_category_test!(test_sysmon_255_sysmon_error, 255, "sysmon_error");

    // ─── PowerShellCore category tests ─────────────────────────────────
    #[test]
    fn test_powershellcore_4103_ps_module() {
        let ls = resolve_logsource("PowerShellCore/Operational", "", 4103, &HashMap::new());
        assert_eq!(ls.service.as_deref(), Some("powershell"));
        assert_eq!(ls.category.as_deref(), Some("ps_module"));
    }

    #[test]
    fn test_powershellcore_4104_ps_script() {
        let ls = resolve_logsource("PowerShellCore/Operational", "", 4104, &HashMap::new());
        assert_eq!(ls.service.as_deref(), Some("powershell"));
        assert_eq!(ls.category.as_deref(), Some("ps_script"));
    }

    // ─── Security category tests ───────────────────────────────────────
    #[test]
    fn test_security_4672_privilege_use() {
        let ls = resolve_logsource("Security", "", 4672, &HashMap::new());
        assert_eq!(ls.service.as_deref(), Some("security"));
        assert_eq!(ls.category.as_deref(), Some("privilege_use"));
    }

    #[test]
    fn test_security_4625_login_failure() {
        let ls = resolve_logsource("Security", "", 4625, &HashMap::new());
        assert_eq!(ls.service.as_deref(), Some("security"));
        assert_eq!(ls.category.as_deref(), Some("login_failure"));
    }

    #[test]
    fn test_security_4634_logoff() {
        let ls = resolve_logsource("Security", "", 4634, &HashMap::new());
        assert_eq!(ls.service.as_deref(), Some("security"));
        assert_eq!(ls.category.as_deref(), Some("logoff"));
    }

    #[test]
    fn test_security_4647_logoff() {
        let ls = resolve_logsource("Security", "", 4647, &HashMap::new());
        assert_eq!(ls.service.as_deref(), Some("security"));
        assert_eq!(ls.category.as_deref(), Some("logoff"));
    }

    // ─── Kernel-File provider (file_access / file_rename) ──────────────
    #[test]
    fn test_kernel_file_provider_fallback() {
        let ls = resolve_logsource("", "Microsoft-Windows-Kernel-File", 0, &HashMap::new());
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service.as_deref(), Some("file"));
        assert_eq!(ls.category, None); // provider fallback only resolves service, not category
    }
}
