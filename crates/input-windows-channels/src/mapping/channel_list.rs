// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! All Windows Event Log channels to collect from.
//!
//! Extracted from `crates/input-windows-channels/src/mapping/channel_mapping.yml`.
//! This is the source of truth for the Winevt channel list.

/// All channels to collect from via Winevt API.
///
/// Extracted from `channel_mapping.yml` — one entry per non-comment,
/// non-blank line (channel name → service mapping).
pub const ALL_CHANNELS: &[&str] = &[
    // 95 channels
    // Standard Windows logs
    "Application",
    "System",
    "Security",
    // Sysmon
    "Microsoft-Windows-Sysmon/Operational",
    // DNS
    "DNS Server",
    "Microsoft-Windows-DNS-Server/Analytical",
    "Microsoft-Windows-DNS-Server/Audit",
    "Microsoft-Windows-DNS Client Events/Operational",
    // DHCP
    "Microsoft-Windows-DHCP-Server/Operational",
    // Driver Frameworks
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    // Hyper-V
    "Microsoft-Windows-Hyper-V-Worker",
    // IIS
    "Microsoft-IIS-Configuration/Operational",
    // Kernel
    "Microsoft-Windows-Kernel-EventTracing",
    "Microsoft-Windows-Kernel-ShimEngine/Operational",
    "Microsoft-Windows-Kernel-ShimEngine/Diagnostic",
    // LDAP
    "Microsoft-Windows-LDAP-Client/Debug",
    // LSA
    "Microsoft-Windows-LSA/Operational",
    // NTLM
    "Microsoft-Windows-NTLM/Operational",
    // NTFS
    "Microsoft-Windows-Ntfs/Operational",
    // OpenSSH
    "OpenSSH/Operational",
    // Print Service
    "Microsoft-Windows-PrintService/Admin",
    "Microsoft-Windows-PrintService/Operational",
    // AppLocker
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    "Microsoft-Windows-AppLocker/Packaged app-Execution",
    // AppModel Runtime
    "Microsoft-Windows-AppModel-Runtime/Admin",
    // AppX
    "Microsoft-Windows-AppXDeploymentServer/Operational",
    "Microsoft-Windows-AppxPackaging/Operational",
    // Application Experience
    "Microsoft-Windows-Application-Experience/Program-Telemetry",
    "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    // BitLocker
    "Microsoft-Windows-BitLocker/BitLocker Management",
    // BITS
    "Microsoft-Windows-Bits-Client/Operational",
    // CAPI2
    "Microsoft-Windows-CAPI2/Operational",
    // Certificate Services Client
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    // Code Integrity
    "Microsoft-Windows-CodeIntegrity/Operational",
    // SENSE
    "Microsoft-Windows-SENSE/Operational",
    // Service Bus
    "Microsoft-ServiceBus-Client/Operational",
    "Microsoft-ServiceBus-Client/Admin",
    // Shell Core
    "Microsoft-Windows-Shell-Core/Operational",
    // Security Mitigations
    "Microsoft-Windows-Security-Mitigations/Kernel Mode",
    "Microsoft-Windows-Security-Mitigations/User Mode",
    // Terminal Services
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    // VHDMP
    "Microsoft-Windows-VHDMP/Operational",
    // Windows Defender
    "Microsoft-Windows-Windows Defender/Operational",
    // Windows Firewall
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    // Diagnosis
    "Microsoft-Windows-Diagnosis-Scripted/Operational",
    // MSExchange
    "MSExchange Management",
    // SMB Client
    "Microsoft-Windows-SmbClient/Security",
    // PowerShell
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "PowerShellCore/Operational",
    // Task Scheduler
    "Microsoft-Windows-TaskScheduler/Operational",
    // WMI
    "Microsoft-Windows-WMI-Activity/Operational",
];
