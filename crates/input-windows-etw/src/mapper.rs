// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! ETW opcode → Sysmon EventID mapping.
//!
//! Each ETW provider emits events with an opcode that maps to a Sysmon
//! EventID. This module provides a jump-table lookup (O(1), zero allocation)
//! to translate ETW opcodes into the Sysmon EID the downstream pipeline
//! expects. When no mapping exists `None` is returned; the caller keeps the
//! raw ETW event_id and routes the event to a dedicated channel.
//!
//! GUIDs are stored as u128 to avoid a ferrisetw dependency in tests.

/// Map an ETW event to its Sysmon EventID.
///
/// The lookup is a jump table — O(1), zero allocation. Returns `None` when no
/// Sysmon equivalent exists; the caller decides how to keep the raw event.
pub fn map_to_sysmon_id(opcode: u8, event_id: u16, provider_guid: u128) -> Option<u16> {
    match (provider_guid, opcode, event_id) {
        // Kernel-Process
        (0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716, 1, _) => Some(1), // process start
        (0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716, 10, _) => Some(7), // image load
        // Kernel-File: opcode 0, routing by EventID
        (0xedd08927_9cc4_4e65_b970_c2560fb5c289, 0, 12) => Some(11), // file create
        (0xedd08927_9cc4_4e65_b970_c2560fb5c289, 0, 16) => Some(11), // file write
        (0xedd08927_9cc4_4e65_b970_c2560fb5c289, 0, 26) => Some(23), // file delete (path)
        (0xedd08927_9cc4_4e65_b970_c2560fb5c289, 0, 27) => Some(23), // file rename (path)
        // Kernel-Network
        (0x7dd42a49_5329_4832_8dfd_43d979153a88, 12, _) => Some(3), // TCP connect
        (0x7dd42a49_5329_4832_8dfd_43d979153a88, 15, _) => Some(3), // UDP
        // Kernel-Registry
        (0x70eb4f03_c1de_4f73_a051_33d13d5413bd, 36, _) => Some(12), // create key
        (0x70eb4f03_c1de_4f73_a051_33d13d5413bd, 39, _) => Some(13), // set value
        (0x70eb4f03_c1de_4f73_a051_33d13d5413bd, 38 | 41, _) => Some(12), // delete key/value
        // DNS-Client: all opcodes → Sysmon 22
        (0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d, _, _) => Some(22),
        // PowerShell: all opcodes → Sysmon 4104
        (0xa0c1853b_5c40_4b15_8766_3cf1c58f985a, _, _) => Some(4104),
        // WMI-Activity: all opcodes → Sysmon 19
        (0x1418ef04_b0b4_4623_bf7e_d74ab47bbdaa, _, _) => Some(19),
        // SCM: all opcodes → Sysmon 7045
        (0x555908d1_a6d7_4695_8e1e_26931d2012f4, _, _) => Some(7045),
        // TaskScheduler: all opcodes → Sysmon 106
        (0xde7b24ea_73c8_4a09_985d_5bdadcfa9017, _, _) => Some(106),
        // Fallback: no Sysmon equivalent
        _ => None,
    }
}

/// Return the synthetic Winevt channel for a Sysmon EventID.
///
/// Most Sysmon EIDs route to `Microsoft-Windows-Sysmon/Operational`.
/// EID 4104 (PowerShell script) routes to the PowerShell operational channel,
/// EID 7045 (service creation) routes to System, and EID 106 (TaskScheduler)
/// routes to the TaskScheduler operational channel.
pub fn synthetic_channel_for_sysmon_eid(sysmon_eid: u16) -> &'static str {
    match sysmon_eid {
        4104 => "Microsoft-Windows-PowerShell/Operational",
        7045 => "System",
        106 => "Microsoft-Windows-TaskScheduler/Operational",
        _ => "Microsoft-Windows-Sysmon/Operational",
    }
}

/// Provider name → Windows event channel for generic (non-Sysmon) routing.
///
/// When an ETW record has no Sysmon EventID equivalent (`map_to_sysmon_id`
/// returns `None`), the record's real EventID is kept and the event is routed to
/// the channel this table maps its provider to. The channel keys must match the
/// `CHANNEL_TO_SERVICE` table in `sigmacatch-types` so `inject_logsource_fields`
/// derives the correct `service`/`category`. This is the extension point for
/// covering more Winevt channels via ETW — adding a provider to `PROVIDERS`
/// only requires a matching entry here (no EventID enumeration needed).
pub static PROVIDER_NAME_TO_CHANNEL: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Security-Auditing" => "Security",
    "Microsoft-Windows-Windows Defender" => "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security" => "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "NTLM Security Protocol" => "Microsoft-Windows-NTLM/Operational",
    "Microsoft-Windows-SMBClient" => "Microsoft-Windows-SmbClient/Security",
    "Local Security Authority (LSA)" => "Microsoft-Windows-LSA/Operational",
    "Microsoft-Windows-Bits-Client" => "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-CAPI2" => "Microsoft-Windows-CAPI2/Operational",
    "Microsoft-Windows-CodeIntegrity" => "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-DNS-Client" => "Microsoft-Windows-DNS Client Events/Operational",
    "Microsoft-Windows-PowerShell" => "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-WMI-Activity" => "Microsoft-Windows-WMI-Activity/Operational",
    "Service Control Manager" => "System",
    "Microsoft-Windows-TaskScheduler" => "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Kernel-Process" => "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Kernel-Network" => "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Kernel-File" => "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Kernel-Registry" => "Microsoft-Windows-Sysmon/Operational",
    "OpenSSH" => "OpenSSH/Operational",
    "Microsoft-Windows-SENSE" => "Microsoft-Windows-SENSE/Operational",
    "Microsoft-Windows-Shell-Core" => "Microsoft-Windows-Shell-Core/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager" => "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode" => "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "Microsoft-Windows-Hyper-V-Worker" => "Microsoft-Windows-Hyper-V-Worker",
    "Microsoft-Windows-Ntfs" => "Microsoft-Windows-Ntfs/Operational",
    "Microsoft-Windows-LDAP-Client" => "Microsoft-Windows-LDAP-Client/Debug",
    "Microsoft-Windows-Diagnosis-Scripted" => "Microsoft-Windows-Diagnosis-Scripted/Operational",
    "Microsoft-Windows-PrintService" => "Microsoft-Windows-PrintService/Operational",
    "Microsoft-Windows-DHCP-Server" => "Microsoft-Windows-DHCP-Server/Operational",
    "Microsoft-Windows-Kernel-EventTracing" => "Microsoft-Windows-Kernel-EventTracing",
    "Microsoft-Windows-Kernel-ShimEngine" => "Microsoft-Windows-Kernel-ShimEngine/Operational",
    "Microsoft-Windows-AppModel-Runtime" => "Microsoft-Windows-AppModel-Runtime/Admin",
    "Microsoft-Windows-AppXDeploymentServer" => "Microsoft-Windows-AppXDeploymentServer/Operational",
    "Microsoft-Windows-AppxPackagingOM" => "Microsoft-Windows-AppxPackaging/Operational",
    "Microsoft-Windows-Application-Experience" => "Microsoft-Windows-Application-Experience/Program-Telemetry",
    "Microsoft-Windows-BitLocker" => "Microsoft-Windows-BitLocker/BitLocker Management",
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System" => "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    "Microsoft-Windows-IIS-Configuration" => "Microsoft-IIS-Configuration/Operational",
    "Microsoft-ServiceBus-Client" => "Microsoft-ServiceBus-Client/Operational",
    "Microsoft-Windows-VHDMP" => "Microsoft-Windows-VHDMP/Operational",
    "Microsoft-Windows-Security-Mitigations" => "Microsoft-Windows-Security-Mitigations/User Mode",
    "Microsoft-Windows-DNS-Server" => "DNS Server",
    "Microsoft-Windows-DNS-Server-Analytical" => "Microsoft-Windows-DNS-Server/Analytical",
    "Microsoft-Windows-DNS-Server-Audit" => "Microsoft-Windows-DNS-Server/Audit",
    "Microsoft-Windows-AppLocker" => "Microsoft-Windows-AppLocker/EXE and DLL",
    "MSExchange Management" => "MSExchange Management",
    "Windows PowerShell" => "Windows PowerShell",
};

/// Route an ETW provider to its Windows event channel for generic (non-Sysmon)
/// events, keeping the record's real EventID. Returns `None` when the provider
/// is unknown — the caller then routes to the dedicated unmapped channel.
pub fn channel_for_provider(provider_name: &str) -> Option<&'static str> {
    PROVIDER_NAME_TO_CHANNEL.get(provider_name).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
    const KERNEL_FILE: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;
    const KERNEL_NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
    const KERNEL_REGISTRY: u128 = 0x70eb4f03_c1de_4f73_a051_33d13d5413bd;
    const DNS_CLIENT: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;
    const POWERSHELL: u128 = 0xa0c1853b_5c40_4b15_8766_3cf1c58f985a;
    const WMI_ACTIVITY: u128 = 0x1418ef04_b0b4_4623_bf7e_d74ab47bbdaa;
    const SCM: u128 = 0x555908d1_a6d7_4695_8e1e_26931d2012f4;
    const TASK_SCHEDULER: u128 = 0xde7b24ea_73c8_4a09_985d_5bdadcfa9017;

    #[test]
    fn test_mapper_process_start() {
        assert_eq!(map_to_sysmon_id(1, 0, KERNEL_PROCESS), Some(1));
    }

    #[test]
    fn test_mapper_image_load() {
        assert_eq!(map_to_sysmon_id(10, 0, KERNEL_PROCESS), Some(7));
    }

    #[test]
    fn test_mapper_file_create() {
        assert_eq!(map_to_sysmon_id(0, 12, KERNEL_FILE), Some(11));
        assert_eq!(map_to_sysmon_id(0, 16, KERNEL_FILE), Some(11));
    }

    #[test]
    fn test_mapper_file_delete() {
        assert_eq!(map_to_sysmon_id(0, 26, KERNEL_FILE), Some(23));
        assert_eq!(map_to_sysmon_id(0, 27, KERNEL_FILE), Some(23));
    }

    #[test]
    fn test_mapper_network_tcp() {
        assert_eq!(map_to_sysmon_id(12, 0, KERNEL_NETWORK), Some(3));
        assert_eq!(map_to_sysmon_id(15, 0, KERNEL_NETWORK), Some(3));
    }

    #[test]
    fn test_mapper_registry() {
        assert_eq!(map_to_sysmon_id(36, 0, KERNEL_REGISTRY), Some(12));
        assert_eq!(map_to_sysmon_id(39, 0, KERNEL_REGISTRY), Some(13));
        assert_eq!(map_to_sysmon_id(38, 0, KERNEL_REGISTRY), Some(12));
        assert_eq!(map_to_sysmon_id(41, 0, KERNEL_REGISTRY), Some(12));
    }

    #[test]
    fn test_mapper_dns() {
        assert_eq!(map_to_sysmon_id(0, 1, DNS_CLIENT), Some(22));
        assert_eq!(map_to_sysmon_id(2, 2, DNS_CLIENT), Some(22));
    }

    #[test]
    fn test_mapper_powershell() {
        assert_eq!(map_to_sysmon_id(0, 0, POWERSHELL), Some(4104));
    }

    #[test]
    fn test_mapper_wmi() {
        assert_eq!(map_to_sysmon_id(0, 0, WMI_ACTIVITY), Some(19));
    }

    #[test]
    fn test_mapper_scm() {
        assert_eq!(map_to_sysmon_id(0, 0, SCM), Some(7045));
    }

    #[test]
    fn test_mapper_taskscheduler() {
        assert_eq!(map_to_sysmon_id(0, 0, TASK_SCHEDULER), Some(106));
    }

    #[test]
    fn test_mapper_unmapped_is_none() {
        assert_eq!(map_to_sysmon_id(99, 42, KERNEL_PROCESS), None);
        assert_eq!(
            map_to_sysmon_id(0, 0, 0xdead_beef_dead_beef_dead_beef_dead_beef),
            None
        );
    }

    #[test]
    fn test_channel_for_sysmon_eid() {
        assert_eq!(
            synthetic_channel_for_sysmon_eid(1),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(3),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(11),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(22),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(4104),
            "Microsoft-Windows-PowerShell/Operational"
        );
        assert_eq!(synthetic_channel_for_sysmon_eid(7045), "System");
        assert_eq!(
            synthetic_channel_for_sysmon_eid(106),
            "Microsoft-Windows-TaskScheduler/Operational"
        );
    }

    #[test]
    fn test_channel_for_provider() {
        assert_eq!(
            channel_for_provider("Microsoft-Windows-Security-Auditing"),
            Some("Security")
        );
        assert_eq!(
            channel_for_provider("Microsoft-Windows-Windows Defender"),
            Some("Microsoft-Windows-Windows Defender/Operational")
        );
        assert_eq!(
            channel_for_provider("NTLM Security Protocol"),
            Some("Microsoft-Windows-NTLM/Operational")
        );
        assert_eq!(
            channel_for_provider("Microsoft-Windows-SMBClient"),
            Some("Microsoft-Windows-SmbClient/Security")
        );
        assert_eq!(channel_for_provider("Unknown-Provider"), None);
    }

    #[test]
    fn test_provider_channel_keys_match_service_table() {
        // Every generic channel must be a key in sigmacatch-types'
        // CHANNEL_TO_SERVICE so inject_logsource_fields derives the service.
        for channel in PROVIDER_NAME_TO_CHANNEL.values() {
            assert!(
                sigmacatch_types::CHANNEL_TO_SERVICE.get(channel).is_some(),
                "channel '{channel}' is not in CHANNEL_TO_SERVICE"
            );
        }
    }
}
