pub mod custom;
pub mod taxonomy;

use std::collections::HashMap;
use rsigma_parser::LogSource;
use taxonomy::{CHANNEL_EVENT_TO_CATEGORY, CHANNEL_TO_SERVICE, PROVIDER_TO_SERVICE};

pub fn resolve_logsource(channel: &str, provider: &str, event_id: u32) -> LogSource {
    if let Some(&service) = CHANNEL_TO_SERVICE.get(channel) {
        let composite_key = format!("{}:{}", channel, event_id);
        let category = CHANNEL_EVENT_TO_CATEGORY.get(&composite_key).copied();
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.to_string()),
            category: category.map(|s| s.to_string()),
            ..LogSource::default()
        };
    }

    if let Some(&service) = PROVIDER_TO_SERVICE.get(provider) {
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.to_string()),
            category: None,
            ..LogSource::default()
        };
    }

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
    pub channel: &'static str,
    pub event_ids: Option<Vec<u32>>,
}

#[allow(dead_code)]
pub fn build_logsource_to_channels() -> HashMap<String, Vec<ChannelTarget>> {
    let mut chan_to_service: Vec<(&'static str, &'static str)> =
        CHANNEL_TO_SERVICE.entries().map(|(k, v)| (*k, *v)).collect();
    chan_to_service.sort_by_key(|(a, _)| *a);

    let mut cat_entries: Vec<(&'static str, &'static str)> =
        CHANNEL_EVENT_TO_CATEGORY.entries().map(|(k, v)| (*k, *v)).collect();
    cat_entries.sort_by_key(|(a, _)| *a);

    let mut map: HashMap<String, HashMap<&'static str, Option<Vec<u32>>>> = HashMap::new();

    for (channel, service) in &chan_to_service {
        map.entry((*service).to_string())
            .or_default()
            .entry(channel)
            .or_insert(None);
    }

    for (key, category) in &cat_entries {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(&service) = CHANNEL_TO_SERVICE.get(channel) {
                    let cat_key = format!("{}:{}", service, category);
                    let eids = map
                        .entry(cat_key)
                        .or_default()
                        .entry(channel)
                        .or_insert_with(|| Some(Vec::new()));
                    if let Some(ref mut v) = eids {
                        v.push(eid);
                    }
                }
            }
        }
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
            targets.sort_by(|a, b| a.channel.cmp(b.channel));
            (key, targets)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_channel_known() {
        let ls = resolve_logsource("Microsoft-Windows-Sysmon/Operational", "", 1);
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service.as_deref(), Some("sysmon"));
        assert_eq!(ls.category.as_deref(), Some("process_creation"));
    }

    #[test]
    fn test_resolve_channel_unknown_provider_fallback() {
        let ls = resolve_logsource("", "Microsoft-Windows-Sysmon", 1);
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service.as_deref(), Some("sysmon"));
    }

    #[test]
    fn test_resolve_both_unknown() {
        let ls = resolve_logsource("UnknownChannel", "UnknownProvider", 0);
        assert_eq!(ls.product.as_deref(), Some("windows"));
        assert_eq!(ls.service, None);
        assert_eq!(ls.category, None);
    }

    #[test]
    fn test_build_sysmon_service_level() {
        let map = build_logsource_to_channels();
        let sysmon = map.get("sysmon").expect("sysmon entry exists");
        assert!(sysmon.iter().any(|t| t.channel == "Microsoft-Windows-Sysmon/Operational"));
        assert!(sysmon.iter().all(|t| t.event_ids.is_none()));
    }

    #[test]
    fn test_build_sysmon_process_creation() {
        let map = build_logsource_to_channels();
        let targets = map.get("sysmon:process_creation").expect("sysmon:process_creation entry exists");
        let t = targets.iter().find(|t| t.channel == "Microsoft-Windows-Sysmon/Operational").unwrap();
        assert_eq!(t.event_ids.as_deref(), Some(&[1u32][..]));
    }

    #[test]
    fn test_build_applocker_multiple_channels() {
        let map = build_logsource_to_channels();
        let applocker = map.get("applocker").expect("applocker entry exists");
        assert!(applocker.len() >= 4, "expected >=4 applocker channels, got {}", applocker.len());
        let names: Vec<&str> = applocker.iter().map(|t| t.channel).collect();
        assert!(names.contains(&"Microsoft-Windows-AppLocker/EXE and DLL"));
        assert!(names.contains(&"Microsoft-Windows-AppLocker/MSI and Script"));
        assert!(names.contains(&"Microsoft-Windows-AppLocker/Packaged app-Deployment"));
        assert!(names.contains(&"Microsoft-Windows-AppLocker/Packaged app-Execution"));
    }

    #[test]
    fn test_build_security_login() {
        let map = build_logsource_to_channels();
        let targets = map.get("security:login").expect("security:login entry exists");
        let t = targets.iter().find(|t| t.channel == "Security").unwrap();
        assert_eq!(t.event_ids.as_deref(), Some(&[4624u32][..]));
    }

    #[test]
    fn test_build_powershell_ps_script() {
        let map = build_logsource_to_channels();
        let targets = map.get("powershell:ps_script").expect("powershell:ps_script entry exists");
        let t = targets.iter().find(|t| t.channel == "Microsoft-Windows-PowerShell/Operational").unwrap();
        assert_eq!(t.event_ids.as_deref(), Some(&[4104u32][..]));
    }

    #[test]
    fn test_build_unknown_key() {
        let map = build_logsource_to_channels();
        assert!(map.get("nonexistent:category").is_none());
    }

    #[test]
    fn test_build_registry_event_merged() {
        let map = build_logsource_to_channels();
        let targets = map.get("sysmon:registry_event").expect("sysmon:registry_event entry exists");
        let t = targets.iter().find(|t| t.channel == "Microsoft-Windows-Sysmon/Operational").unwrap();
        let eids = t.event_ids.as_deref().unwrap();
        assert!(eids.contains(&12));
        assert!(eids.contains(&13));
        assert!(eids.contains(&14));
    }
}
