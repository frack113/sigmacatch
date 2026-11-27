// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows ETW decoding helpers shared by the ETW and kernel-sensor inputs.
//!
//! The pure format modules compile on every target, so their unit tests run
//! in the Linux CI legs too. The Win32-backed helpers are empty off Windows.

pub mod pe_format;
pub mod registry_format;
pub mod wmi_format;

#[cfg(target_os = "windows")]
pub mod etw_event;
#[cfg(target_os = "windows")]
pub mod etw_process;
#[cfg(target_os = "windows")]
pub mod etw_registry;
#[cfg(target_os = "windows")]
pub mod etw_sysmon;
#[cfg(target_os = "windows")]
pub mod nt_file;
#[cfg(target_os = "windows")]
pub mod signature;
#[cfg(target_os = "windows")]
pub mod version_info;
