// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Static seed of ETW providers subscribed by the collector.
//!
//! Provider GUIDs are kept as canonical UUID strings (not raw GUID fields): the
//! 128-bit value cannot be encoded losslessly in a few `u16`/`u64` tuples
//! without byte-order pitfalls, while `windows::core::GUID::from(&str)` parses
//! the canonical form directly. Tests validate format + uniqueness on any
//! platform (no Windows required).

/// An ETW provider to enable, with its subscription keywords and level.
pub struct EtwProvider {
    /// Provider name, used as `Provider@Name` in the synthesized XML — feeds
    /// the `PROVIDER_TO_SERVICE` mapping in `sigmacatch-types`.
    pub name: &'static str,
    /// Provider GUID in canonical UUID form (`8-4-4-4-12`, hex).
    pub guid: &'static str,
    /// Any-keyword mask — events matching any of these keywords are delivered.
    pub keywords: u64,
    /// Enable level (4 = Information; 5 = Verbose).
    pub level: u8,
}

/// Providers the collector subscribes to.
///
/// The first 9 are the high-fidelity Sysmon-style providers (kernel providers,
/// DNS, PS, WMI, SCM, TaskScheduler) — their events are masqueraded as Sysmon
/// EventIDs by [`crate::mapper`]. The rest are the additional Windows channels
/// (Security, Defender, Firewall, NTLM, SMB, LSA, CAPI2, CodeIntegrity, …)
/// routed generically by provider name → channel (real EventID kept) via
/// [`crate::mapper::channel_for_provider`]. Kernel providers and Security-Auditing
/// need admin rights to enable.
pub const PROVIDERS: [EtwProvider; 18] = [
    // ─── Sysmon-style (high-fidelity, opcode → Sysmon EventID) ───────────────
    EtwProvider {
        name: "Microsoft-Windows-Kernel-Process",
        guid: "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
        keywords: 0x50,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-Kernel-Network",
        guid: "7dd42a49-5329-4832-8dfd-43d979153a88",
        keywords: 0x30,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-Kernel-File",
        guid: "edd08927-9cc4-4e65-b970-c2560fb5c289",
        keywords: 0xE90,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-Kernel-Registry",
        guid: "70eb4f03-c1de-4f73-a051-33d13d5413bd",
        keywords: 0xF000,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-DNS-Client",
        guid: "1c95126e-7eea-49a9-a3fe-a378b03ddb4d",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-PowerShell",
        guid: "A0C1853B-5C40-4B15-8766-3CF1C58F985A",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-WMI-Activity",
        guid: "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Service Control Manager",
        guid: "555908d1-a6d7-4695-8e1e-26931d2012f4",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-TaskScheduler",
        guid: "de7b24ea-73c8-4a09-985d-5bdadcfa9017",
        keywords: u64::MAX,
        level: 4,
    },
    // ─── Generic channels (provider → channel, real EventID kept) ────────────
    EtwProvider {
        name: "Microsoft-Windows-Security-Auditing",
        guid: "54849625-5478-4994-a5ba-3e3b0328c30d",
        keywords: 0x9000_0000_0000_0000, // Audit Success (0x8020…) + Failure (0x8010…)
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-Windows Defender",
        guid: "11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-Windows Firewall With Advanced Security",
        guid: "d1bc9aff-2abf-4d71-9146-ecb2a986eb85",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "NTLM Security Protocol",
        guid: "c92cf544-91b3-4dc0-8e11-c580339a0bf8",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-SMBClient",
        guid: "988c59c5-0a1c-45b6-a555-0c62276e327d",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Local Security Authority (LSA)",
        guid: "cc85922f-db41-11d2-9244-006008269001",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-Bits-Client",
        guid: "ef1cc15b-46c1-414e-bb95-e76b077bd51e",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-CAPI2",
        guid: "5bbca4a8-b209-48dc-a8c7-b23d3e5216fb",
        keywords: u64::MAX,
        level: 4,
    },
    EtwProvider {
        name: "Microsoft-Windows-CodeIntegrity",
        guid: "4ee76bd8-3cf4-44a0-a0ac-3937643e37a3",
        keywords: u64::MAX,
        level: 4,
    },
];

/// Whether `s` is a canonical UUID string (`8-4-4-4-12` hex, non-zero).
#[cfg(test)]
fn is_valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 || b.iter().all(|c| matches!(c, b'0' | b'-')) {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_providers_guid_valid() {
        for p in PROVIDERS {
            assert!(
                is_valid_uuid(p.guid),
                "invalid GUID for provider '{}': {}",
                p.name,
                p.guid
            );
        }
    }

    #[test]
    fn test_providers_no_duplicates() {
        let mut guids: Vec<&str> = PROVIDERS.iter().map(|p| p.guid).collect();
        guids.sort();
        guids.dedup();
        assert_eq!(guids.len(), PROVIDERS.len(), "duplicate provider GUIDs");
    }

    #[test]
    fn test_providers_level_range() {
        for p in PROVIDERS {
            assert!(
                (0..=5).contains(&p.level),
                "provider '{}' has out-of-range level {}",
                p.name,
                p.level
            );
        }
    }

    #[test]
    fn test_providers_keywords_nonzero() {
        for p in PROVIDERS {
            assert_ne!(p.keywords, 0, "provider '{}' subscribes to nothing", p.name);
        }
    }
}
