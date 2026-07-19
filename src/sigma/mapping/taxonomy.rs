// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use phf::phf_map;

// ─── Channel → Service (table principale, ~50 entrées) ─────────────────
pub static CHANNEL_TO_SERVICE: phf::Map<&'static str, &'static str> = phf_map! {
    "Microsoft-Windows-Sysmon/Operational" => "sysmon",
    "Security" => "security",
    "System" => "system",
    "Application" => "application",
    "Windows PowerShell" => "powershell-classic",
    "Microsoft-Windows-PowerShell/Operational" => "powershell",
    "PowerShellCore/Operational" => "powershell",
    "Microsoft-Windows-Windows Defender/Operational" => "windefend",
    "Microsoft-Windows-TaskScheduler/Operational" => "taskscheduler",
    "Microsoft-Windows-WMI-Activity/Operational" => "wmi",
    "Microsoft-Windows-DNS Client Events/Operational" => "dns-client",
    "Microsoft-Windows-DNS-Client/Operational" => "dns-client",
    "DNS Server" => "dns-server",
    "Microsoft-Windows-DNS-Server/Analytical" => "dns-server-analytic",
    "Microsoft-Windows-DNS-Server/Audit" => "dns-server-audit",
    "Microsoft-Windows-AppLocker/EXE and DLL" => "applocker",
    "Microsoft-Windows-AppLocker/MSI and Script" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Execution" => "applocker",
    "Microsoft-Windows-Bits-Client/Operational" => "bits-client",
    "Microsoft-Windows-DHCP-Server/Operational" => "dhcp",
    "Microsoft-Windows-Diagnosis-Scripted/Operational" => "diagnosis-scripted",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational" => "driver-framework",
    "Microsoft-Windows-BitLocker/BitLocker Management" => "bitlocker",
    "Microsoft-Windows-CAPI2/Operational" => "capi2",
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" => "certificateservicesclient-lifecycle-system",
    "Microsoft-Windows-CodeIntegrity/Operational" => "codeintegrity-operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" => "firewall-as",
    "Microsoft-Windows-Hyper-V-Worker" => "hyper-v-worker",
    "Microsoft-IIS-Configuration/Operational" => "iis-configuration",
    "Microsoft-Windows-Kernel-EventTracing" => "kernel-event-tracing",
    "Microsoft-Windows-Kernel-ShimEngine/Operational" => "kernel-shimengine",
    "Microsoft-Windows-Kernel-ShimEngine/Diagnostic" => "kernel-shimengine",
    "Microsoft-Windows-LDAP-Client/Debug" => "ldap",
    "Microsoft-Windows-LSA/Operational" => "lsa-server",
    "MSExchange Management" => "msexchange-management",
    "Microsoft-Windows-Ntfs/Operational" => "ntfs",
    "Microsoft-Windows-NTLM/Operational" => "ntlm",
    "OpenSSH/Operational" => "openssh",
    "Microsoft-Windows-PrintService/Admin" => "printservice-admin",
    "Microsoft-Windows-PrintService/Operational" => "printservice-operational",
    "Microsoft-Windows-Security-Mitigations/Kernel Mode" => "security-mitigations",
    "Microsoft-Windows-Security-Mitigations/User Mode" => "security-mitigations",
    "Microsoft-Windows-SENSE/Operational" => "sense",
    "Microsoft-ServiceBus-Client/Operational" => "servicebus-client",
    "Microsoft-ServiceBus-Client/Admin" => "servicebus-client",
    "Microsoft-Windows-Shell-Core/Operational" => "shell-core",
    "Microsoft-Windows-SmbClient/Security" => "smbclient-security",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" => "terminalservices-localsessionmanager",
    "Microsoft-Windows-VHDMP/Operational" => "vhdmp",
    "Microsoft-Windows-Application-Experience/Program-Telemetry" => "application-experience",
    "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" => "application-experience",
    "Microsoft-Windows-AppModel-Runtime/Admin" => "appmodel-runtime",
    "Microsoft-Windows-AppXDeploymentServer/Operational" => "appxdeployment-server",
    "Microsoft-Windows-AppxPackaging/Operational" => "appxpackaging-om",
    "Microsoft-Windows-Kernel-PnP/Device Configuration" => "pnp",
};

// ─── Provider → Service (fallback strict, channel inconnu) ────────────
pub static PROVIDER_TO_SERVICE: phf::Map<&'static str, &'static str> = phf_map! {
    "Microsoft-Windows-Sysmon" => "sysmon",
    "Microsoft-Windows-Security-Auditing" => "security",
    "Microsoft-Windows-PowerShell" => "powershell",
    "Microsoft-Windows-Windows Defender" => "windefend",
    "Service Control Manager" => "system",
    "Microsoft-Windows-Kernel-Process" => "process",
    "Microsoft-Windows-Kernel-Network" => "network",
    "Microsoft-Windows-Kernel-File" => "file",
    "Microsoft-Windows-Kernel-Registry" => "registry",
    "Microsoft-Windows-DNS-Client" => "dns",
};

// ─── Channel:EventID → Category (clé composite "channel:eid") ─────────
pub static CHANNEL_EVENT_TO_CATEGORY: phf::Map<&'static str, &'static str> = phf_map! {
    // Sysmon
    "Microsoft-Windows-Sysmon/Operational:1" => "process_creation",
    "Microsoft-Windows-Sysmon/Operational:2" => "file_change",
    "Microsoft-Windows-Sysmon/Operational:3" => "network_connection",
    "Microsoft-Windows-Sysmon/Operational:4" => "sysmon_status",
    "Microsoft-Windows-Sysmon/Operational:5" => "process_termination",
    "Microsoft-Windows-Sysmon/Operational:6" => "driver_load",
    "Microsoft-Windows-Sysmon/Operational:7" => "image_load",
    "Microsoft-Windows-Sysmon/Operational:8" => "create_remote_thread",
    "Microsoft-Windows-Sysmon/Operational:9" => "raw_access_thread",
    "Microsoft-Windows-Sysmon/Operational:10" => "process_access",
    "Microsoft-Windows-Sysmon/Operational:11" => "file_event",
    "Microsoft-Windows-Sysmon/Operational:12" => "registry_event",
    "Microsoft-Windows-Sysmon/Operational:13" => "registry_event",
    "Microsoft-Windows-Sysmon/Operational:14" => "registry_event",
    "Microsoft-Windows-Sysmon/Operational:15" => "create_stream_hash",
    "Microsoft-Windows-Sysmon/Operational:16" => "sysmon_status",
    "Microsoft-Windows-Sysmon/Operational:17" => "pipe_created",
    "Microsoft-Windows-Sysmon/Operational:18" => "pipe_created",
    "Microsoft-Windows-Sysmon/Operational:19" => "wmi_event",
    "Microsoft-Windows-Sysmon/Operational:20" => "wmi_event",
    "Microsoft-Windows-Sysmon/Operational:21" => "wmi_event",
    "Microsoft-Windows-Sysmon/Operational:22" => "dns_query",
    "Microsoft-Windows-Sysmon/Operational:23" => "file_delete",
    "Microsoft-Windows-Sysmon/Operational:24" => "clipboard_capture",
    "Microsoft-Windows-Sysmon/Operational:25" => "process_tampering",
    "Microsoft-Windows-Sysmon/Operational:26" => "file_delete_detected",
    "Microsoft-Windows-Sysmon/Operational:27" => "file_block_executable",
    "Microsoft-Windows-Sysmon/Operational:28" => "file_block_shredding",
    "Microsoft-Windows-Sysmon/Operational:29" => "file_executable_detected",
    "Microsoft-Windows-Sysmon/Operational:255" => "sysmon_error",
    // Security
    "Security:4688" => "process_creation",
    "Security:4672" => "privilege_use",
    "Security:4625" => "login_failure",
    "Security:4624" => "login",
    "Security:4634" => "logoff",
    "Security:4647" => "logoff",
    // PowerShell classic (Windows PowerShell channel)
    "Windows PowerShell:400" => "ps_classic_start",
    "Windows PowerShell:600" => "ps_classic_provider_start",
    "Windows PowerShell:800" => "ps_classic_script",
    // PowerShell modern (Operational channel)
    "Microsoft-Windows-PowerShell/Operational:4103" => "ps_module",
    "Microsoft-Windows-PowerShell/Operational:4104" => "ps_script",
    // PowerShellCore
    "PowerShellCore/Operational:4103" => "ps_module",
    "PowerShellCore/Operational:4104" => "ps_script",
};

// ─── Sub-category overrides (plus spécifique, prioritaire sur category) ─
// phf_map ne supporte pas les clés dupliquées, donc les sous-catégories
// sont stockées dans une map séparée.
// Pour EventID 12 (registry_add + registry_delete), la désambiguïsation
// se fait à runtime via EventType (DeleteValue/DeleteKey → registry_delete).
pub static CHANNEL_EVENT_TO_SUBCATEGORY: phf::Map<&'static str, &'static str> = phf_map! {
    "Microsoft-Windows-Sysmon/Operational:12" => "registry_add",
    "Microsoft-Windows-Sysmon/Operational:13" => "registry_set",
    "Microsoft-Windows-Sysmon/Operational:14" => "registry_rename",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_to_service_sysmon() {
        assert_eq!(
            CHANNEL_TO_SERVICE.get("Microsoft-Windows-Sysmon/Operational"),
            Some(&"sysmon")
        );
    }

    #[test]
    fn test_channel_to_service_security() {
        assert_eq!(CHANNEL_TO_SERVICE.get("Security"), Some(&"security"));
    }

    #[test]
    fn test_channel_to_service_unknown() {
        assert!(CHANNEL_TO_SERVICE.get("UnknownChannel").is_none());
    }

    #[test]
    fn test_provider_to_service_sysmon() {
        assert_eq!(
            PROVIDER_TO_SERVICE.get("Microsoft-Windows-Sysmon"),
            Some(&"sysmon")
        );
    }

    #[test]
    fn test_provider_to_service_fallback() {
        assert_eq!(
            PROVIDER_TO_SERVICE.get("Microsoft-Windows-Kernel-Process"),
            Some(&"process")
        );
    }

    #[test]
    fn test_provider_to_service_unknown() {
        assert!(PROVIDER_TO_SERVICE.get("UnknownProvider").is_none());
    }

    #[test]
    fn test_channel_event_to_category_sysmon_1() {
        assert_eq!(
            CHANNEL_EVENT_TO_CATEGORY.get("Microsoft-Windows-Sysmon/Operational:1"),
            Some(&"process_creation")
        );
    }

    #[test]
    fn test_channel_event_to_category_security_4688() {
        assert_eq!(
            CHANNEL_EVENT_TO_CATEGORY.get("Security:4688"),
            Some(&"process_creation")
        );
    }

    #[test]
    fn test_channel_event_to_category_ps_4104() {
        assert_eq!(
            CHANNEL_EVENT_TO_CATEGORY.get("Microsoft-Windows-PowerShell/Operational:4104"),
            Some(&"ps_script")
        );
    }

    #[test]
    fn test_channel_event_to_category_ps_classic_800() {
        assert_eq!(
            CHANNEL_EVENT_TO_CATEGORY.get("Windows PowerShell:800"),
            Some(&"ps_classic_script")
        );
    }

    #[test]
    fn test_channel_event_to_category_unknown() {
        assert!(CHANNEL_EVENT_TO_CATEGORY.get("Security:0").is_none());
    }
}
