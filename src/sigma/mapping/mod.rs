pub mod custom;
pub mod taxonomy;

use rsigma_parser::LogSource;
use std::collections::HashMap;
use taxonomy::{
    CHANNEL_EVENT_TO_CATEGORY, CHANNEL_EVENT_TO_SUBCATEGORY, CHANNEL_TO_SERVICE,
    PROVIDER_TO_SERVICE,
};
use tracing::debug;

/// Resolve LogSource from channel, provider, and event_id.
///
/// INVARIANT: channel > provider > default
/// Priority order MUST NOT be changed:
///   1. Channel → service (CHANNEL_TO_SERVICE + custom_map override)
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
    let lookup_service = |ch: &str| -> Option<String> {
        if let Some(service) = custom_map.get(ch) {
            return Some(service.clone());
        }
        CHANNEL_TO_SERVICE.get(ch).map(|s| s.to_string())
    };

    if let Some(service) = lookup_service(channel) {
        let composite_key = format!("{}:{}", channel, event_id);
        let category = CHANNEL_EVENT_TO_SUBCATEGORY
            .get(&composite_key)
            .copied()
            .or_else(|| CHANNEL_EVENT_TO_CATEGORY.get(&composite_key).copied());
        debug!(
            "LogSource resolved via channel: service={}, category={:?}",
            service, category
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service),
            category: category.map(|s| s.to_string()),
            ..LogSource::default()
        };
    }

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

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChannelTarget {
    pub channel: String,
    pub event_ids: Option<Vec<u32>>,
}

#[allow(dead_code)]
pub fn build_logsource_to_channels(
    custom_map: &HashMap<String, String>,
) -> HashMap<String, Vec<ChannelTarget>> {
    let mut chan_to_service: Vec<(&'static str, &'static str)> = CHANNEL_TO_SERVICE
        .entries()
        .map(|(k, v)| (*k, *v))
        .collect();
    chan_to_service.sort_by_key(|(a, _)| *a);

    let mut cat_entries: Vec<(&'static str, &'static str)> = CHANNEL_EVENT_TO_CATEGORY
        .entries()
        .map(|(k, v)| (*k, *v))
        .chain(
            CHANNEL_EVENT_TO_SUBCATEGORY
                .entries()
                .map(|(k, v)| (*k, *v)),
        )
        .collect();
    cat_entries.sort_by_key(|(a, _)| *a);

    let mut map: HashMap<String, HashMap<String, Option<Vec<u32>>>> = HashMap::new();

    for (channel, service) in &chan_to_service {
        map.entry((*service).to_string())
            .or_default()
            .entry((*channel).to_string())
            .or_insert(None);
    }

    for (key, category) in &cat_entries {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE.get(channel) {
                    let cat_key = format!("{}:{}", service, category);
                    let eids = map
                        .entry(cat_key)
                        .or_default()
                        .entry(channel.to_string())
                        .or_insert_with(|| Some(Vec::new()));
                    if let Some(ref mut v) = eids {
                        v.push(eid);
                    }
                }
            }
        }
    }

    for (channel, service) in custom_map {
        map.entry(service.clone())
            .or_default()
            .entry(channel.clone())
            .or_insert(None);
    }

    map.into_iter()
        .map(|(key, channels)| {
            let mut targets: Vec<ChannelTarget> = channels
                .into_iter()
                .filter_map(|(channel, eids)| {
                    if eids.as_ref().is_none_or(|v| v.is_empty()) {
                        Some(ChannelTarget {
                            channel,
                            event_ids: None,
                        })
                    } else {
                        eids.map(|mut v| {
                            v.sort();
                            v.dedup();
                            ChannelTarget {
                                channel,
                                event_ids: Some(v),
                            }
                        })
                    }
                })
                .collect();
            targets.sort_by(|a, b| a.channel.cmp(&b.channel));
            (key, targets)
        })
        .collect()
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
