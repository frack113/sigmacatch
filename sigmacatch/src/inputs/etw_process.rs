// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Live-process facts: the fields ETW does not publish.
//!
//! `Microsoft-Windows-Kernel-Process` reports a process start with its PID,
//! parent, creation time and a device-path image, but never its **command
//! line** or its **user**. Both exist only in the live process: the command
//! line in the process parameters and the user on its token. This module reads
//! them while the process is still alive, which is why the process session is
//! flushed every few milliseconds.
//!
//! Everything here is exact — the values come from the kernel, not from a
//! heuristic — which is what lets the Sysmon-schema event carry them under the
//! project's fidelity rule.

use std::ffi::c_void;
use std::mem::size_of;

use chrono::{DateTime, Utc};
use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation,
};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSID, SID_NAME_USE, TOKEN_INFORMATION_CLASS,
    TOKEN_QUERY, TokenIntegrityLevel, TokenUser,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_BASIC_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR};

/// Everything we can read about a live process.
#[derive(Debug, Clone, Default)]
pub struct ProcessFacts {
    /// Process id.
    pub pid: u32,
    /// Id of the creating process.
    pub parent_pid: u32,
    /// Full DOS image path, e.g. `C:\Windows\System32\cmd.exe`.
    pub image: Option<String>,
    /// Full command line, as the process received it.
    pub command_line: Option<String>,
    /// `DOMAIN\user` (or `MACHINE\user`) resolved from the token user SID.
    pub user: Option<String>,
    /// Token user SID, e.g. `S-1-5-21-...`.
    pub user_sid: Option<String>,
    /// Mandatory label name, e.g. `High` (Sysmon's `IntegrityLevel`).
    pub integrity: Option<String>,
    /// Process creation time, from `GetProcessTimes`.
    pub created: Option<DateTime<Utc>>,
}

/// Current process ids, from a Toolhelp snapshot.
///
/// Used as the creation trigger when the realtime ETW stream does not carry
/// process-start records: the snapshot is cheap (a few hundred microseconds on
/// a desktop-sized process table) and the fields still come from the live
/// process, so polling only bounds *when* a process is noticed, never what is
/// reported about it.
pub fn snapshot() -> Vec<u32> {
    // SAFETY: the snapshot handle is closed before returning.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return Vec::new();
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut pids = Vec::new();
    // SAFETY: `entry` is sized as the API requires.
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            pids.push(entry.th32ProcessID);
            // SAFETY: same entry, advanced in place.
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    // SAFETY: handle came from `CreateToolhelp32Snapshot` exactly once.
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    pids
}

/// Read the live facts for `pid`, or `None` when the process is gone or
/// inaccessible (protected processes, a process that already exited).
///
/// Individual fields degrade to `None`: a process we may open but not read is
/// still worth reporting by image and PID.
pub fn enrich(pid: u32) -> Option<ProcessFacts> {
    if pid == 0 {
        return None;
    }
    // SAFETY: the handle is closed before returning; every sub-call only reads.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let facts = ProcessFacts {
        pid,
        parent_pid: parent_pid(handle).unwrap_or(0),
        image: image_path(handle),
        command_line: command_line(handle),
        created: created(handle),
        ..token_facts(handle).unwrap_or_default()
    };
    // SAFETY: handle came from `OpenProcess` exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    Some(facts)
}

/// Full DOS image path.
fn image_path(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 1024];
    let mut length = buffer.len() as u32;
    // SAFETY: buffer and length describe the same allocation.
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            Default::default(),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
        .ok()?
    };
    Some(String::from_utf16_lossy(&buffer[..length as usize]))
}

/// Command line, through `ProcessCommandLineInformation`.
///
/// The returned `UNICODE_STRING` points into a buffer the kernel owns for the
/// duration of the call, so the string is copied out immediately.
fn command_line(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u8; 8192];
    let mut returned = 0u32;
    // SAFETY: buffer is writable for its whole length.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len() as u32,
            &mut returned,
        )
    };
    if status.0 < 0 {
        return None;
    }
    // `UNICODE_STRING`: Length (u16), MaximumLength (u16), padding, Buffer.
    let length = u16::from_ne_bytes([buffer[0], buffer[1]]) as usize;
    let pointer = usize::from_ne_bytes(buffer.get(8..16)?.try_into().ok()?);
    if length == 0 || pointer == 0 {
        return None;
    }
    // SAFETY: the kernel wrote a `Buffer` pointer to `length` bytes of UTF-16.
    let units = unsafe { std::slice::from_raw_parts(pointer as *const u16, length / 2) };
    Some(String::from_utf16_lossy(units))
}

/// Parent process id, through `ProcessBasicInformation`.
fn parent_pid(handle: HANDLE) -> Option<u32> {
    let mut basic = PROCESS_BASIC_INFORMATION::default();
    let mut returned = 0u32;
    // SAFETY: `basic` is exactly the size the API writes.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            std::ptr::addr_of_mut!(basic).cast::<c_void>(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if status.0 < 0 {
        return None;
    }
    u32::try_from(basic.InheritedFromUniqueProcessId).ok()
}

/// Creation time, from the process kernel object.
fn created(handle: HANDLE) -> Option<DateTime<Utc>> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: four distinct out-parameters.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).ok()? };
    let ticks = i64::from(creation.dwLowDateTime) | (i64::from(creation.dwHighDateTime) << 32);
    crate::inputs::etw_event::filetime_to_utc(ticks)
}

/// User SID/name and mandatory label from the process token.
fn token_facts(handle: HANDLE) -> Option<ProcessFacts> {
    let mut token = HANDLE::default();
    // SAFETY: token is closed before returning.
    unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token).ok()? };

    let user = token_sid_strings(token, TokenUser);
    let integrity =
        token_sid_strings(token, TokenIntegrityLevel).and_then(|(sid, _)| integrity_name(&sid));

    // SAFETY: token came from `OpenProcessToken` exactly once.
    unsafe {
        let _ = CloseHandle(token);
    }
    let (user_sid, user) = user.map_or((None, None), |(sid, name)| (Some(sid), name));
    Some(ProcessFacts {
        user,
        user_sid,
        integrity,
        ..ProcessFacts::default()
    })
}

/// SID string and account name carried by a `TOKEN_USER` or
/// `TOKEN_MANDATORY_LABEL` buffer.
///
/// The SID lives inside a local buffer, so both conversions happen here, while
/// it is alive; the caller only ever sees owned strings.
fn token_sid_strings(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
) -> Option<(String, Option<String>)> {
    let mut buffer = [0u8; 256];
    let mut returned = 0u32;
    // SAFETY: buffer is writable and the size matches.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            buffer.len() as u32,
            &mut returned,
        )
        .ok()?
    };
    if returned == 0 {
        return None;
    }
    // Both structures start with `SID_AND_ATTRIBUTES { Sid: PSID, Attributes }`.
    let raw = usize::from_ne_bytes(buffer.get(0..8)?.try_into().ok()?);
    if raw == 0 {
        return None;
    }
    let sid = PSID(raw as *mut c_void);
    let name = sid_name(sid);
    Some((sid_string(sid)?, name))
}

fn sid_string(sid: PSID) -> Option<String> {
    let mut raw = PWSTR::null();
    // SAFETY: the SID comes from a live token buffer; the returned string is
    // freed with `LocalFree`.
    unsafe { ConvertSidToStringSidW(sid, &mut raw).ok()? };
    // Read the wide string by hand: `PWSTR`'s `Display` impl returns an error
    // on malformed UTF-16, and `to_string` would panic inside the callback.
    let text = unsafe { wide_string(raw.0) };
    // SAFETY: converted pointer came from the `LocalAlloc` inside the call.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(raw.0.cast::<c_void>())));
    }
    Some(text)
}

/// Copy a NUL-terminated wide string, lossily.
unsafe fn wide_string(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    while unsafe { *pointer.add(length) } != 0 && length < 4096 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn sid_name(sid: PSID) -> Option<String> {
    let mut name = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    // SAFETY: four out-parameters describe distinct buffers.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
        .ok()?
    };
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Some(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

/// Map the integrity SID to the name Sysmon writes (`High`, `Medium`, ...).
fn integrity_name(sid: &str) -> Option<String> {
    let rid = sid.rsplit('-').next()?;
    Some(
        match rid {
            "0" => "Untrusted",
            "4096" => "Low",
            "8192" => "Medium",
            "8448" => "Medium Plus",
            "12288" => "High",
            "16384" => "System",
            "20480" => "Protected Process",
            _ => return None,
        }
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_integrity_levels() {
        assert_eq!(integrity_name("S-1-16-12288").as_deref(), Some("High"));
        assert_eq!(integrity_name("S-1-16-8192").as_deref(), Some("Medium"));
        assert_eq!(integrity_name("S-1-16-16384").as_deref(), Some("System"));
        assert_eq!(integrity_name("S-1-16-1"), None);
    }
}
