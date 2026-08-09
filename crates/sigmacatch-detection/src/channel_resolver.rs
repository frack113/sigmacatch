// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows event channel resolution from **post-pipeline** rule logsources.
//!
//! The `windows` pipeline rewrites every sysmon-routed category to
//! `service: sysmon` (see `pipelines/windows.yml`), so the compiled rule
//! logsource is the single source of truth: category → service lives in the
//! pipeline, service → channel lives here. Rules whose category the pipeline
//! does not touch (ps_module, ps_script, ...) fall back to their category.

use rsigma_eval::compiler::CompiledRule;
use std::collections::{HashMap, HashSet};

/// Service → Windows event channels. Covers every `service:` seen in
/// Windows Sigma rules; the sysmon category routing is implied by the
/// `windows` pipeline instead of being duplicated here.
static SERVICE_CHANNELS: phf::Map<&'static str, &'static [&'static str]> = phf::phf_map! {
    "application" => &["Application"],
    "application-experience" => &[
        "Microsoft-Windows-Application-Experience/Program-Telemetry",
        "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    ],
    "applocker" => &[
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ],
    "appmodel-runtime" => &["Microsoft-Windows-AppModel-Runtime/Admin"],
    "appxdeployment-server" => &["Microsoft-Windows-AppXDeploymentServer/Operational"],
    "appxpackaging-om" => &["Microsoft-Windows-AppxPackaging/Operational"],
    "bitlocker" => &["Microsoft-Windows-BitLocker/BitLocker Management"],
    "bits-client" => &["Microsoft-Windows-Bits-Client/Operational"],
    "capi2" => &["Microsoft-Windows-CAPI2/Operational"],
    "certificateservicesclient-lifecycle-system" => &[
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    ],
    "codeintegrity-operational" => &["Microsoft-Windows-CodeIntegrity/Operational"],
    "dhcp" => &["Microsoft-Windows-DHCP-Server/Operational"],
    "diagnosis-scripted" => &["Microsoft-Windows-Diagnosis-Scripted/Operational"],
    "dns-client" => &["Microsoft-Windows-DNS Client Events/Operational"],
    "dns-server" => &["DNS Server"],
    "dns-server-analytic" => &["Microsoft-Windows-DNS-Server/Analytical"],
    "dns-server-audit" => &["Microsoft-Windows-DNS-Server/Audit"],
    "driver-framework" => &["Microsoft-Windows-DriverFrameworks-UserMode/Operational"],
    "firewall-as" => &[
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    ],
    "hyper-v-worker" => &["Microsoft-Windows-Hyper-V-Worker"],
    "iis-configuration" => &["Microsoft-IIS-Configuration/Operational"],
    "kernel-event-tracing" => &["Microsoft-Windows-Kernel-EventTracing"],
    "kernel-shimengine" => &[
        "Microsoft-Windows-Kernel-ShimEngine/Operational",
        "Microsoft-Windows-Kernel-ShimEngine/Diagnostic",
    ],
    "ldap" => &["Microsoft-Windows-LDAP-Client/Debug"],
    "lsa-server" => &["Microsoft-Windows-LSA/Operational"],
    "msexchange-management" => &["MSExchange Management"],
    "ntfs" => &["Microsoft-Windows-Ntfs/Operational"],
    "ntlm" => &["Microsoft-Windows-NTLM/Operational"],
    "openssh" => &["OpenSSH/Operational"],
    "powershell" => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    "powershell-classic" => &["Windows PowerShell"],
    "printservice-admin" => &["Microsoft-Windows-PrintService/Admin"],
    "printservice-operational" => &["Microsoft-Windows-PrintService/Operational"],
    "security" => &["Security"],
    "security-mitigations" => &[
        "Microsoft-Windows-Security-Mitigations/Kernel Mode",
        "Microsoft-Windows-Security-Mitigations/User Mode",
    ],
    "sense" => &["Microsoft-Windows-SENSE/Operational"],
    "servicebus-client" => &[
        "Microsoft-ServiceBus-Client/Operational",
        "Microsoft-ServiceBus-Client/Admin",
    ],
    "shell-core" => &["Microsoft-Windows-Shell-Core/Operational"],
    "smbclient-security" => &["Microsoft-Windows-SmbClient/Security"],
    "sysmon" => &["Microsoft-Windows-Sysmon/Operational"],
    "system" => &["System"],
    "taskscheduler" => &["Microsoft-Windows-TaskScheduler/Operational"],
    "terminalservices-localsessionmanager" => &[
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    ],
    "vhdmp" => &["Microsoft-Windows-VHDMP/Operational"],
    "windefend" => &["Microsoft-Windows-Windows Defender/Operational"],
    "wmi" => &["Microsoft-Windows-WMI-Activity/Operational"],
};

/// Category → Windows event channels for categories the `windows` pipeline
/// does not route (no EventID mapping). Sysmon categories are intentionally
/// absent — the pipeline rewrites them to `service: sysmon`.
static CATEGORY_CHANNELS: phf::Map<&'static str, &'static [&'static str]> = phf::phf_map! {
    "ps_classic_provider_start" => &["Windows PowerShell"],
    "ps_classic_script" => &["Windows PowerShell"],
    "ps_classic_start" => &["Windows PowerShell"],
    "ps_module" => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    "ps_script" => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
};

/// Resolve the union of Windows event channels to collect for the given
/// compiled rules. Logsources are post-pipeline, so sysmon-routed categories
/// already carry `service: sysmon`.
pub(crate) fn resolve_channels(
    rules: &[CompiledRule],
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
        let ls = &rule.logsource;
        if !ls
            .product
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case("windows"))
            .unwrap_or(false)
        {
            continue;
        }

        let service = ls.service.as_deref();
        let category = ls.category.as_deref();

        let mut targets: Vec<&str> = Vec::new();
        if let Some(s) = service {
            // Sigma `service` is conventionally lowercase, but normalize the
            // lookup so a mixed-case value (e.g. "Sysmon") still resolves.
            let service_key = s.to_ascii_lowercase();
            if let Some(static_targets) = SERVICE_CHANNELS.get(service_key.as_str()) {
                targets.extend(static_targets.iter().copied());
            }
            for (channel, custom_service) in custom_map {
                if custom_service.as_str().eq_ignore_ascii_case(s) {
                    targets.push(channel);
                }
            }
        } else if let Some(c) = category {
            let category_key = c.to_ascii_lowercase();
            if let Some(static_targets) = CATEGORY_CHANNELS.get(category_key.as_str()) {
                targets.extend(static_targets.iter().copied());
            }
        }

        if targets.is_empty() {
            if service.is_none() && category.is_none() {
                rules_without_logsource += 1;
            } else {
                unresolved_rules += 1;
                unresolved_logsources.insert(format!(
                    "{}:{}",
                    service.unwrap_or("*"),
                    category.unwrap_or("*")
                ));
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
