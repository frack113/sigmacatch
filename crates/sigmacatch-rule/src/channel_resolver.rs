// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::SigmaRule;
use std::collections::{HashMap, HashSet};

/// Composite logsource key: `(service, category)`. An empty string means the
/// field is absent from the rule's `logsource`.
type Logsource = (&'static str, &'static str);

/// Static table of Sigma logsource → Windows Event Log channels to collect.
///
/// Keys:
/// - `(service, "")` — rule with only a `service`
/// - `("", category)` — rule with only a `category`
/// - `(service, category)` — rule with both
static LOGSOURCE_CHANNELS: phf::Map<Logsource, &'static [&'static str]> = phf::phf_map! {
    ("application", "") => &["Application"],
    ("application-experience", "") => &[
        "Microsoft-Windows-Application-Experience/Program-Telemetry",
        "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    ],
    ("applocker", "") => &[
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ],
    ("appmodel-runtime", "") => &["Microsoft-Windows-AppModel-Runtime/Admin"],
    ("appxdeployment-server", "") => &["Microsoft-Windows-AppXDeploymentServer/Operational"],
    ("appxpackaging-om", "") => &["Microsoft-Windows-AppxPackaging/Operational"],
    ("bitlocker", "") => &["Microsoft-Windows-BitLocker/BitLocker Management"],
    ("bits-client", "") => &["Microsoft-Windows-Bits-Client/Operational"],
    ("capi2", "") => &["Microsoft-Windows-CAPI2/Operational"],
    ("certificateservicesclient-lifecycle-system", "") => &[
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    ],
    ("codeintegrity-operational", "") => &["Microsoft-Windows-CodeIntegrity/Operational"],
    ("dhcp", "") => &["Microsoft-Windows-DHCP-Server/Operational"],
    ("diagnosis-scripted", "") => &["Microsoft-Windows-Diagnosis-Scripted/Operational"],
    ("dns-client", "") => &["Microsoft-Windows-DNS Client Events/Operational"],
    ("dns-server", "") => &["DNS Server"],
    ("dns-server-analytic", "") => &["Microsoft-Windows-DNS-Server/Analytical"],
    ("dns-server-audit", "") => &["Microsoft-Windows-DNS-Server/Audit"],
    ("driver-framework", "") => &["Microsoft-Windows-DriverFrameworks-UserMode/Operational"],
    ("firewall-as", "") => &[
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    ],
    ("hyper-v-worker", "") => &["Microsoft-Windows-Hyper-V-Worker"],
    ("iis-configuration", "") => &["Microsoft-IIS-Configuration/Operational"],
    ("kernel-event-tracing", "") => &["Microsoft-Windows-Kernel-EventTracing"],
    ("kernel-shimengine", "") => &[
        "Microsoft-Windows-Kernel-ShimEngine/Operational",
        "Microsoft-Windows-Kernel-ShimEngine/Diagnostic",
    ],
    ("ldap", "") => &["Microsoft-Windows-LDAP-Client/Debug"],
    ("lsa-server", "") => &["Microsoft-Windows-LSA/Operational"],
    ("msexchange-management", "") => &["MSExchange Management"],
    ("ntfs", "") => &["Microsoft-Windows-Ntfs/Operational"],
    ("ntlm", "") => &["Microsoft-Windows-NTLM/Operational"],
    ("openssh", "") => &["OpenSSH/Operational"],
    ("powershell", "") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("powershell-classic", "") => &["Windows PowerShell"],
    ("printservice-admin", "") => &["Microsoft-Windows-PrintService/Admin"],
    ("printservice-operational", "") => &["Microsoft-Windows-PrintService/Operational"],
    ("security", "") => &["Security"],
    ("security-mitigations", "") => &[
        "Microsoft-Windows-Security-Mitigations/Kernel Mode",
        "Microsoft-Windows-Security-Mitigations/User Mode",
    ],
    ("sense", "") => &["Microsoft-Windows-SENSE/Operational"],
    ("servicebus-client", "") => &[
        "Microsoft-ServiceBus-Client/Operational",
        "Microsoft-ServiceBus-Client/Admin",
    ],
    ("shell-core", "") => &["Microsoft-Windows-Shell-Core/Operational"],
    ("smbclient-security", "") => &["Microsoft-Windows-SmbClient/Security"],
    ("sysmon", "") => &["Microsoft-Windows-Sysmon/Operational"],
    ("system", "") => &["System"],
    ("taskscheduler", "") => &["Microsoft-Windows-TaskScheduler/Operational"],
    ("terminalservices-localsessionmanager", "") => &[
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    ],
    ("vhdmp", "") => &["Microsoft-Windows-VHDMP/Operational"],
    ("windefend", "") => &["Microsoft-Windows-Windows Defender/Operational"],
    ("wmi", "") => &["Microsoft-Windows-WMI-Activity/Operational"],

    ("", "clipboard_capture") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "create_remote_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "create_stream_hash") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "dns_query") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "driver_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_block_executable") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_block_shredding") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_change") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_delete") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_delete_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "file_executable_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "image_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "login") => &["Security"],
    ("", "login_failure") => &["Security"],
    ("", "logoff") => &["Security"],
    ("", "network_connection") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "pipe_created") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "privilege_use") => &["Security"],
    ("", "process_access") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "process_creation") => &[
        "Microsoft-Windows-Sysmon/Operational",
        "Security",
    ],
    ("", "process_tampering") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "process_termination") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "ps_classic_provider_start") => &["Windows PowerShell"],
    ("", "ps_classic_script") => &["Windows PowerShell"],
    ("", "ps_classic_start") => &["Windows PowerShell"],
    ("", "ps_module") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("", "ps_script") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("", "raw_access_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "registry_add") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "registry_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "registry_rename") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "registry_set") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "sysmon_error") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "sysmon_status") => &["Microsoft-Windows-Sysmon/Operational"],
    ("", "wmi_event") => &["Microsoft-Windows-Sysmon/Operational"],

    ("powershell", "ps_module") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("powershell", "ps_script") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("powershell-classic", "ps_classic_provider_start") => &["Windows PowerShell"],
    ("powershell-classic", "ps_classic_script") => &["Windows PowerShell"],
    ("powershell-classic", "ps_classic_start") => &["Windows PowerShell"],
    ("security", "login") => &["Security"],
    ("security", "login_failure") => &["Security"],
    ("security", "logoff") => &["Security"],
    ("security", "privilege_use") => &["Security"],
    ("security", "process_creation") => &["Security"],
    ("sysmon", "clipboard_capture") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "create_remote_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "create_stream_hash") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "dns_query") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "driver_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_block_executable") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_block_shredding") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_change") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_delete") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_delete_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "file_executable_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "image_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "network_connection") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "pipe_created") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "process_access") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "process_creation") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "process_tampering") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "process_termination") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "raw_access_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "registry_add") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "registry_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "registry_rename") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "registry_set") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "sysmon_error") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "sysmon_status") => &["Microsoft-Windows-Sysmon/Operational"],
    ("sysmon", "wmi_event") => &["Microsoft-Windows-Sysmon/Operational"],
};

/// Resolve the Windows Event Log channels required by the given rules.
///
/// For each loaded Windows rule, determines the channels to collect from its
/// `logsource.service` and `logsource.category`. Only channels justified by at
/// least one loaded rule are returned — there is no fail-open fallback.
///
/// Resolution is strict: an unmapped logsource (unknown service/category, or a
/// rule with no logsource at all) contributes no channels and is reported via
/// a warning. Such rules will simply not produce regression data.
pub(crate) fn resolve_channels(
    rules: &[SigmaRule],
    custom_map: &HashMap<String, String>,
) -> Vec<String> {
    if rules.is_empty() {
        tracing::info!("No rules loaded — cannot resolve channels");
        return Vec::new();
    }

    let mut channels_set: HashSet<String> = HashSet::new();
    let mut unresolved_rules: usize = 0;
    let mut unresolved_logsources: HashSet<String> = HashSet::new();
    let mut rules_without_logsource: usize = 0;

    for rule in rules {
        if !rule
            .logsource
            .product
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case("windows"))
            .unwrap_or(false)
        {
            continue;
        }

        let service = rule.logsource.service.as_deref();
        let category = rule.logsource.category.as_deref();
        let mut targets: Vec<&str> = Vec::new();

        match (service, category) {
            (Some(service), Some(category)) => {
                if let Some(static_targets) = LOGSOURCE_CHANNELS.get(&(service, category)) {
                    targets.extend(static_targets.iter().copied());
                }
            }
            (Some(service), None) => {
                if let Some(static_targets) = LOGSOURCE_CHANNELS.get(&(service, "")) {
                    targets.extend(static_targets.iter().copied());
                }
                for (channel, custom_service) in custom_map {
                    if custom_service == service {
                        targets.push(channel);
                    }
                }
            }
            (None, Some(category)) => {
                if let Some(static_targets) = LOGSOURCE_CHANNELS.get(&("", category)) {
                    targets.extend(static_targets.iter().copied());
                }
            }
            (None, None) => {}
        }

        if targets.is_empty() {
            match (service, category) {
                (None, None) => rules_without_logsource += 1,
                (service, category) => {
                    unresolved_rules += 1;
                    unresolved_logsources.insert(format!(
                        "{}:{}",
                        service.unwrap_or("*"),
                        category.unwrap_or("*")
                    ));
                }
            }
        } else {
            channels_set.extend(targets.into_iter().map(str::to_string));
        }
    }

    if rules_without_logsource > 0 {
        tracing::warn!(
            "{rules_without_logsource} rules have no logsource (service/category) — no channels resolved from them"
        );
    }
    if unresolved_rules > 0 {
        let mut sorted: Vec<String> = unresolved_logsources.into_iter().collect();
        sorted.sort();
        tracing::warn!(
            "{unresolved_rules} rules with unmapped logsource (service/category) — no channels resolved from them: {sorted:?}"
        );
    }

    let mut channels: Vec<String> = channels_set.into_iter().collect();
    channels.sort();

    tracing::info!("Channels to collect: {:?}", channels);

    channels
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_sigma_yaml;
    use crate::SigmaCollection;

    fn parse_rule(logsource: &str) -> SigmaCollection {
        let yaml = format!(
            "title: test rule\nid: test-rule\nlogsource:\n{logsource}\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\n"
        );
        parse_sigma_yaml(&yaml).expect("rule must parse")
    }

    fn resolve(logsource: &str) -> Vec<String> {
        resolve_channels(&parse_rule(logsource).rules, &HashMap::new())
    }

    fn resolve_multi(logsources: &[&str]) -> Vec<String> {
        let mut collection = SigmaCollection::default();
        for ls in logsources {
            let parsed = parse_rule(ls);
            collection.rules.extend(parsed.rules);
        }
        resolve_channels(&collection.rules, &HashMap::new())
    }

    #[test]
    fn test_resolve_service_only() {
        let channels = resolve("  product: windows\n  service: sysmon\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_service_category() {
        let channels =
            resolve("  product: windows\n  service: sysmon\n  category: process_creation\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_category_only_spans_services() {
        // process_creation exists on both Sysmon:1 and Security:4688.
        let channels = resolve("  product: windows\n  category: process_creation\n");
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Security".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_subcategory() {
        let channels = resolve("  product: windows\n  service: sysmon\n  category: registry_add\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_parent_category() {
        let channels = resolve("  product: windows\n  category: registry_event\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_unknown_service_strict_no_fallback() {
        // Strict: unknown service:category contributes nothing, even though
        // the service alone would resolve.
        let channels =
            resolve("  product: windows\n  service: sysmon\n  category: bogus_category\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_unknown_service() {
        let channels = resolve("  product: windows\n  service: nonexistent\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_unknown_category() {
        let channels = resolve("  product: windows\n  category: nonexistent\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_no_logsource() {
        let channels = resolve("  product: windows\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_ignores_non_windows() {
        let channels = resolve("  product: linux\n  category: process_creation\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_union_across_rules() {
        let channels = resolve_multi(&[
            "  product: windows\n  service: sysmon\n  category: process_creation\n",
            "  product: windows\n  service: security\n  category: login\n",
        ]);
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Security".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_custom_map() {
        let mut custom_map = HashMap::new();
        custom_map.insert(
            "Custom-Channel/Operational".to_string(),
            "sysmon".to_string(),
        );
        let collection = parse_rule("  product: windows\n  service: sysmon\n");
        let channels = resolve_channels(&collection.rules, &custom_map);
        assert_eq!(
            channels,
            vec![
                "Custom-Channel/Operational".to_string(),
                "Microsoft-Windows-Sysmon/Operational".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_custom_map_service_category_untouched() {
        // Custom map only extends the service-only resolution path.
        let mut custom_map = HashMap::new();
        custom_map.insert(
            "Custom-Channel/Operational".to_string(),
            "sysmon".to_string(),
        );
        let collection =
            parse_rule("  product: windows\n  service: sysmon\n  category: process_creation\n");
        let channels = resolve_channels(&collection.rules, &custom_map);
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_empty_collection() {
        let collection = SigmaCollection::default();
        let channels = resolve_channels(&collection.rules, &HashMap::new());
        assert!(channels.is_empty());
    }
}
