// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! ETW → Sysmon field renaming tables.
//!
//! Each ETW provider emits its own field names (e.g. `ImageName`, `daddr`).
//! The Sigma rules in the registry expect Sysmon field names (e.g. `Image`,
//! `DestinationIp`). This module provides the mapping between the two.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Process,
    File,
    Network,
    Dns,
    PowerShell,
    WmiActivity,
    Scm,
    TaskScheduler,
}

#[derive(Debug, Clone)]
pub struct FieldMapping {
    etw_to_sigma: HashMap<&'static str, &'static str>,
}

impl FieldMapping {
    pub fn new(sigma_to_etw: &[(&'static str, &'static str)]) -> Self {
        Self {
            etw_to_sigma: sigma_to_etw.iter().map(|(s, e)| (*e, *s)).collect(),
        }
    }

    pub fn etw_name_to_sigma_name(&self, key: &str) -> Option<&str> {
        self.etw_to_sigma.get(key).copied()
    }

    /// The ETW-side field names, for parsing only the mapped subset.
    pub fn etw_names(&self) -> Vec<&'static str> {
        self.etw_to_sigma.keys().copied().collect()
    }
}

/// Return the field mapping for a given provider kind.
pub fn field_map_for_provider(kind: ProviderKind) -> &'static FieldMapping {
    match kind {
        ProviderKind::Process => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[
                    ("Image", "ImageName"),
                    ("ParentImage", "ParentImageName"),
                    ("CommandLine", "CommandLine"),
                    ("ParentCommandLine", "ParentCommandLine"),
                    ("ProcessId", "ProcessID"),
                    ("ParentProcessId", "ParentProcessID"),
                    ("User", "UserName"),
                    ("LogonId", "LogonId"),
                    ("LogonGuid", "LogonGuid"),
                    ("CurrentDirectory", "CurrentDirectory"),
                    ("IntegrityLevel", "IntegrityLevel"),
                ])
            })
        }
        ProviderKind::File => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[("TargetFilename", "FileName"), ("Image", "ImageName")])
            })
        }
        ProviderKind::Network => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[
                    ("DestinationIp", "daddr"),
                    ("DestinationPort", "dport"),
                    ("SourceIp", "saddr"),
                    ("SourcePort", "sport"),
                    ("Protocol", "Protocol"),
                ])
            })
        }
        ProviderKind::Dns => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[("QueryName", "QueryName"), ("QueryResults", "QueryResults")])
            })
        }
        ProviderKind::PowerShell => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[
                    ("ScriptBlockText", "ScriptBlockText"),
                    ("ScriptBlockId", "ScriptBlockId"),
                ])
            })
        }
        ProviderKind::WmiActivity => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[
                    ("Query", "Query"),
                    ("EventNamespace", "EventNamespace"),
                    ("Operation", "Operation"),
                ])
            })
        }
        ProviderKind::Scm => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[("ServiceName", "ServiceName"), ("ImagePath", "ImagePath")])
            })
        }
        ProviderKind::TaskScheduler => {
            static MAP: std::sync::OnceLock<FieldMapping> = std::sync::OnceLock::new();
            MAP.get_or_init(|| {
                FieldMapping::new(&[("TaskName", "TaskName"), ("UserContext", "UserName")])
            })
        }
    }
}

/// Rename ETW fields to Sysmon field names for the given provider kind.
///
/// Returns a new HashMap with renamed keys. Empty/whitespace values are
/// skipped; the stored value is trimmed.
pub fn rename_fields(
    fields: &HashMap<String, String>,
    kind: ProviderKind,
) -> HashMap<String, String> {
    let mapping = field_map_for_provider(kind);
    fields
        .iter()
        .filter_map(|(k, v)| {
            let value = v.trim();
            if value.is_empty() {
                return None;
            }
            if let Some(sigma_key) = mapping.etw_name_to_sigma_name(k) {
                Some((sigma_key.to_string(), value.to_string()))
            } else {
                Some((k.clone(), value.to_string()))
            }
        })
        .collect()
}

/// Return the provider kind for a known ETW provider name, if any.
///
/// Unknown providers map to `None`: their fields are not parsed and the event
/// is routed to the dedicated unmapped channel.
pub fn provider_kind_for_name(name: &str) -> Option<ProviderKind> {
    match name {
        "Microsoft-Windows-Kernel-Process" => Some(ProviderKind::Process),
        "Microsoft-Windows-Kernel-File" => Some(ProviderKind::File),
        "Microsoft-Windows-Kernel-Network" => Some(ProviderKind::Network),
        // Registry fields are not in the spec; the Process map covers the
        // kernel event subset that overlaps (TargetObject/Details excluded).
        "Microsoft-Windows-Kernel-Registry" => Some(ProviderKind::Process),
        "Microsoft-Windows-DNS-Client" => Some(ProviderKind::Dns),
        "Microsoft-Windows-PowerShell" => Some(ProviderKind::PowerShell),
        "Microsoft-Windows-WMI-Activity" => Some(ProviderKind::WmiActivity),
        "Service Control Manager" => Some(ProviderKind::Scm),
        "Microsoft-Windows-TaskScheduler" => Some(ProviderKind::TaskScheduler),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_fields() {
        let mut etw = HashMap::new();
        etw.insert("ImageName".to_string(), "/usr/bin/foo".to_string());
        etw.insert("CommandLine".to_string(), "foo --bar".to_string());
        etw.insert("ParentImageName".to_string(), "/usr/bin/bar".to_string());
        etw.insert("ProcessID".to_string(), "4242".to_string());
        etw.insert("UserName".to_string(), "papa".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Process);
        assert_eq!(renamed.get("Image"), Some(&"/usr/bin/foo".to_string()));
        assert_eq!(renamed.get("CommandLine"), Some(&"foo --bar".to_string()));
        assert_eq!(
            renamed.get("ParentImage"),
            Some(&"/usr/bin/bar".to_string())
        );
        assert_eq!(renamed.get("ProcessId"), Some(&"4242".to_string()));
        assert_eq!(renamed.get("User"), Some(&"papa".to_string()));
        assert_eq!(renamed.get("ImageName"), None); // renamed away
    }

    #[test]
    fn test_file_fields() {
        let mut etw = HashMap::new();
        etw.insert("FileName".to_string(), "/etc/passwd".to_string());
        etw.insert("ImageName".to_string(), "/usr/bin/cat".to_string());
        let renamed = rename_fields(&etw, ProviderKind::File);
        assert_eq!(renamed.get("FileName"), None);
        assert_eq!(
            renamed.get("TargetFilename"),
            Some(&"/etc/passwd".to_string())
        );
        assert_eq!(renamed.get("Image"), Some(&"/usr/bin/cat".to_string()));
    }

    #[test]
    fn test_network_fields() {
        let mut etw = HashMap::new();
        etw.insert("DestinationIp".to_string(), "192.168.1.1".to_string());
        etw.insert("DestinationPort".to_string(), "443".to_string());
        etw.insert("SourceIp".to_string(), "10.0.0.1".to_string());
        etw.insert("SourcePort".to_string(), "12345".to_string());
        etw.insert("Protocol".to_string(), "TCP".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Network);
        assert_eq!(
            renamed.get("DestinationIp"),
            Some(&"192.168.1.1".to_string())
        );
        assert_eq!(renamed.get("DestinationPort"), Some(&"443".to_string()));
        assert_eq!(renamed.get("SourceIp"), Some(&"10.0.0.1".to_string()));
        assert_eq!(renamed.get("SourcePort"), Some(&"12345".to_string()));
        assert_eq!(renamed.get("Protocol"), Some(&"TCP".to_string()));
    }

    #[test]
    fn test_dns_fields() {
        let mut etw = HashMap::new();
        etw.insert("QueryName".to_string(), "evil.com".to_string());
        etw.insert("QueryResults".to_string(), "1.2.3.4".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Dns);
        assert_eq!(renamed.get("QueryName"), Some(&"evil.com".to_string()));
        assert_eq!(renamed.get("QueryResults"), Some(&"1.2.3.4".to_string()));
    }

    #[test]
    fn test_powershell_fields() {
        let mut etw = HashMap::new();
        etw.insert(
            "ScriptBlockText".to_string(),
            "Invoke-WebRequest".to_string(),
        );
        let renamed = rename_fields(&etw, ProviderKind::PowerShell);
        assert_eq!(
            renamed.get("ScriptBlockText"),
            Some(&"Invoke-WebRequest".to_string())
        );
    }

    #[test]
    fn test_scm_fields() {
        let mut etw = HashMap::new();
        etw.insert("ServiceName".to_string(), "evil_svc".to_string());
        etw.insert("ImagePath".to_string(), "C:\\evil.exe".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Scm);
        assert_eq!(renamed.get("ServiceName"), Some(&"evil_svc".to_string()));
        assert_eq!(renamed.get("ImagePath"), Some(&"C:\\evil.exe".to_string()));
    }

    #[test]
    fn test_taskscheduler_fields() {
        let mut etw = HashMap::new();
        etw.insert("TaskName".to_string(), "evil_task".to_string());
        etw.insert("UserContext".to_string(), "SYSTEM".to_string());
        let renamed = rename_fields(&etw, ProviderKind::TaskScheduler);
        assert_eq!(renamed.get("TaskName"), Some(&"evil_task".to_string()));
        assert_eq!(renamed.get("UserContext"), Some(&"SYSTEM".to_string()));
    }

    #[test]
    fn test_empty_values_skipped() {
        let mut etw = HashMap::new();
        etw.insert("ImageName".to_string(), "".to_string());
        etw.insert("CommandLine".to_string(), "foo".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Process);
        assert_eq!(renamed.get("Image"), None);
        assert_eq!(renamed.get("CommandLine"), Some(&"foo".to_string()));
    }

    #[test]
    fn test_unmapped_fields_preserved() {
        let mut etw = HashMap::new();
        etw.insert("UnknownField".to_string(), "value".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Process);
        assert_eq!(renamed.get("UnknownField"), Some(&"value".to_string()));
    }

    #[test]
    fn test_trim_skips_whitespace_only() {
        let mut etw = HashMap::new();
        etw.insert("ImageName".to_string(), "   ".to_string());
        let renamed = rename_fields(&etw, ProviderKind::Process);
        assert_eq!(renamed.get("Image"), None);
    }

    #[test]
    fn test_provider_kind_for_name() {
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-Kernel-Process"),
            Some(ProviderKind::Process)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-Kernel-File"),
            Some(ProviderKind::File)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-Kernel-Network"),
            Some(ProviderKind::Network)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-Kernel-Registry"),
            Some(ProviderKind::Process)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-DNS-Client"),
            Some(ProviderKind::Dns)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-PowerShell"),
            Some(ProviderKind::PowerShell)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-WMI-Activity"),
            Some(ProviderKind::WmiActivity)
        );
        assert_eq!(
            provider_kind_for_name("Service Control Manager"),
            Some(ProviderKind::Scm)
        );
        assert_eq!(
            provider_kind_for_name("Microsoft-Windows-TaskScheduler"),
            Some(ProviderKind::TaskScheduler)
        );
        assert_eq!(provider_kind_for_name("Microsoft-Windows-Foo"), None);
    }

    #[test]
    fn test_etw_names_round_trip() {
        let mapping = field_map_for_provider(ProviderKind::Process);
        let names = mapping.etw_names();
        assert!(names.contains(&"ImageName"));
        assert!(names.contains(&"ProcessID"));
        assert!(names.contains(&"UserName"));
    }
}
