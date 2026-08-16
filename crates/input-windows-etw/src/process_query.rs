// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! On-demand process queries (Windows) backing the enrichment cache (AD-7).
//!
//! Every query is **fail-open** (returns `None`): a dead process, a WOW64
//! process whose PEB layout differs, or an access-denied token query never
//! loses an event — the field is simply absent. Callers cache the result in
//! the [`crate::process_table::ProcessTable`] entry and re-validate against
//! `CreateTime` before reuse.

use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Maximum bytes of PEB CommandLine to read (fail-open bound).
const MAX_COMMAND_LINE_BYTES: usize = 8192;

fn filetime_to_quad(ft: &FILETIME) -> i64 {
    (u64::from(ft.dwHighDateTime) << 32 | u64::from(ft.dwLowDateTime)) as i64
}

fn open_process(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Option<HANDLE> {
    unsafe { OpenProcess(access, false, pid).ok() }
}

/// Current `CreateTime` of a process as a FILETIME quad (100ns since 1601),
/// the same unit as Kernel-Process event 1 `CreateTime`. `None` on failure
/// (process gone, insufficient rights).
pub fn query_create_time(pid: u32) -> Option<i64> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) };
    let _ = unsafe { CloseHandle(handle) };
    ok.ok().map(|()| filetime_to_quad(&create))
}

/// Executable path of a process as a Win32 path (`C:\…`). `None` on failure.
pub fn query_image_path(pid: u32) -> Option<String> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    ok.ok()
        .map(|()| String::from_utf16_lossy(&buf[..len as usize]))
}

/// Parent PID of a process via `NtQueryInformationProcess(ProcessBasicInformation)`.
/// `None` on failure.
pub fn query_parent_pid(pid: u32) -> Option<u32> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let result = query_parent_pid_with(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

#[cfg(target_arch = "x86_64")]
fn query_parent_pid_with(handle: HANDLE) -> Option<u32> {
    #[repr(C)]
    struct ProcessBasicInformation {
        reserved1: *mut core::ffi::c_void,
        peb_base_address: *mut core::ffi::c_void,
        reserved2: [*mut core::ffi::c_void; 2],
        unique_process_id: *mut core::ffi::c_void,
        inherited_from_unique_process_id: *mut core::ffi::c_void,
    }

    let mut basic = ProcessBasicInformation {
        reserved1: core::ptr::null_mut(),
        peb_base_address: core::ptr::null_mut(),
        reserved2: [core::ptr::null_mut(); 2],
        unique_process_id: core::ptr::null_mut(),
        inherited_from_unique_process_id: core::ptr::null_mut(),
    };
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESSINFOCLASS(0), // ProcessBasicInformation
            (&mut basic as *mut ProcessBasicInformation).cast(),
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            core::ptr::null_mut(),
        )
    };
    if status.0 < 0 {
        return None;
    }
    let parent = basic.inherited_from_unique_process_id as usize;
    if parent == 0 || parent > u32::MAX as usize {
        return None;
    }
    Some(parent as u32)
}

#[cfg(not(target_arch = "x86_64"))]
fn query_parent_pid_with(_handle: HANDLE) -> Option<u32> {
    None
}

/// CommandLine of a process read from its PEB (`NtQueryInformationProcess` +
/// `ReadProcessMemory`). x64 layout only; WOW64 or unreadable PEB → `None`.
///
/// The PEB structs are not bound by the `windows` crate (native NT types), so
/// the minimal fields are laid out by hand — they are stable across x64.
///
/// `ReadProcessMemory` requires `PROCESS_VM_READ` on the handle (plus query
/// access for `NtQueryInformationProcess`), so the open rights are wider than
/// for `query_image_path`/`query_create_time`.
pub fn query_command_line(pid: u32) -> Option<String> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let result = query_command_line_with(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

/// Current working directory of a process (PEB `CurrentDirectory.DosPath`),
/// the value Sysmon reports as `CurrentDirectory`. `None` on failure.
pub fn query_current_directory(pid: u32) -> Option<String> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let result = query_current_directory_with(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

/// x64 layout (stable NT): PEB.ProcessParameters at 0x20.
#[cfg(target_arch = "x86_64")]
const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20;

#[cfg(target_arch = "x86_64")]
fn query_command_line_with(handle: HANDLE) -> Option<String> {
    let parameters = process_parameters(handle)?;
    // RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING at 0x70).
    read_unicode_string(handle, parameters + 0x70)
}

#[cfg(target_arch = "x86_64")]
fn query_current_directory_with(handle: HANDLE) -> Option<String> {
    let parameters = process_parameters(handle)?;
    // RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath: CURDIR { UNICODE_STRING
    // DosPath, HANDLE Handle }, so the UNICODE_STRING is at 0x38.
    read_unicode_string(handle, parameters + 0x38)
}

/// Address of `RTL_USER_PROCESS_PARAMETERS` via `NtQueryInformationProcess`
/// (ProcessBasicInformation) + PEB read. x64 layout only.
#[cfg(target_arch = "x86_64")]
fn process_parameters(handle: HANDLE) -> Option<usize> {
    #[repr(C)]
    struct ProcessBasicInformation {
        reserved1: *mut core::ffi::c_void,
        peb_base_address: *mut core::ffi::c_void,
        reserved2: [*mut core::ffi::c_void; 2],
        unique_process_id: *mut core::ffi::c_void,
        inherited_from_unique_process_id: *mut core::ffi::c_void,
    }

    let mut basic = ProcessBasicInformation {
        reserved1: core::ptr::null_mut(),
        peb_base_address: core::ptr::null_mut(),
        reserved2: [core::ptr::null_mut(); 2],
        unique_process_id: core::ptr::null_mut(),
        inherited_from_unique_process_id: core::ptr::null_mut(),
    };
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESSINFOCLASS(0), // ProcessBasicInformation
            (&mut basic as *mut ProcessBasicInformation).cast(),
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            core::ptr::null_mut(),
        )
    };
    if status.0 < 0 {
        return None;
    }
    let peb = basic.peb_base_address as usize;
    if peb == 0 {
        return None;
    }
    let mut parameters: usize = 0;
    if !read_ptr(handle, peb + PEB_PROCESS_PARAMETERS_OFFSET, &mut parameters) || parameters == 0 {
        return None;
    }
    Some(parameters)
}

/// Read an x64 `UNICODE_STRING` at `off` in the target process (bounded).
#[cfg(target_arch = "x86_64")]
fn read_unicode_string(handle: HANDLE, off: usize) -> Option<String> {
    #[repr(C)]
    #[derive(Default)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut us = UnicodeString::default();
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            off as *const core::ffi::c_void,
            (&mut us as *mut UnicodeString).cast(),
            core::mem::size_of::<UnicodeString>(),
            Some(&mut read),
        )
    };
    if ok.is_err() || read != core::mem::size_of::<UnicodeString>() {
        return None;
    }
    let byte_len = us.length as usize;
    if byte_len == 0 || byte_len > MAX_COMMAND_LINE_BYTES || us.buffer.is_null() {
        return None;
    }
    let mut buf = vec![0u16; byte_len / 2];
    read = 0;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            us.buffer.cast(),
            buf.as_mut_ptr().cast(),
            byte_len,
            Some(&mut read),
        )
    };
    if ok.is_err() || read != byte_len {
        return None;
    }
    let s = String::from_utf16_lossy(&buf);
    let s = s.trim_matches('\0').trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(not(target_arch = "x86_64"))]
fn query_command_line_with(_handle: HANDLE) -> Option<String> {
    // PEB offsets below are x64-only; WOW64/32-bit targets fail open.
    None
}

#[cfg(not(target_arch = "x86_64"))]
fn query_current_directory_with(_handle: HANDLE) -> Option<String> {
    None
}

/// Read a pointer-sized value at `address` in the target process.
#[cfg(target_arch = "x86_64")]
fn read_ptr(handle: HANDLE, address: usize, out: &mut usize) -> bool {
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const core::ffi::c_void,
            (out as *mut usize).cast(),
            core::mem::size_of::<usize>(),
            Some(&mut read),
        )
    };
    ok.is_ok() && read == core::mem::size_of::<usize>()
}

/// Domain-qualified user name (`DOMAIN\user`) of the process token owner,
/// via `OpenProcessToken` + `GetTokenInformation(TokenUser)` +
/// `LookupAccountSidW`. `None` on failure (access denied, process gone).
pub fn query_user_name(pid: u32) -> Option<String> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION)?;
    let result = query_user_name_with(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

fn query_user_name_with(handle: HANDLE) -> Option<String> {
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, PSID, SID, SID_NAME_USE, TOKEN_QUERY, TokenUser,
    };

    let mut token = HANDLE::default();
    let ok = unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) };
    if ok.is_err() || token.is_invalid() {
        return None;
    }
    let result = (|| {
        // First call with null buffer returns the required size.
        let mut size = 0u32;
        let rc = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut size) };
        if rc.is_err() || size == 0 || size > 4096 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                size,
                &mut size,
            )
        };
        if rc.is_err() {
            return None;
        }
        // TOKEN_USER { SID_AND_ATTRIBUTES { SID* , Attributes } } — the SID
        // pointer is the first field.
        #[repr(C)]
        struct TokenUserLayout {
            sid: *mut SID,
            attributes: u32,
        }
        let token_user = unsafe { &*(buf.as_ptr().cast::<TokenUserLayout>()) };
        if token_user.sid.is_null() {
            return None;
        }
        let sid = token_user.sid;

        // LookupAccountSidW: two-pass for the account and domain names.
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut use_: SID_NAME_USE = Default::default();
        let _ = unsafe {
            LookupAccountSidW(
                None,
                PSID(sid.cast()),
                None,
                &mut name_len,
                None,
                &mut domain_len,
                &mut use_,
            )
        };
        if name_len == 0 {
            return None;
        }
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let rc = unsafe {
            LookupAccountSidW(
                None,
                PSID(sid.cast()),
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut use_,
            )
        };
        if rc.is_err() {
            return None;
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize - 1]);
        let domain = String::from_utf16_lossy(&domain[..domain_len.saturating_sub(1) as usize]);
        let account = if name.is_empty() {
            "?".to_string()
        } else {
            name
        };
        Some(if domain.is_empty() {
            account
        } else {
            format!("{domain}\\{account}")
        })
    })();
    let _ = unsafe { CloseHandle(token) };
    result
}

/// Integrity level of the process token (last SID sub-authority of
/// `TokenIntegrityLevel`), e.g. `High`. `None` on failure.
pub fn query_integrity_level(pid: u32) -> Option<String> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION)?;
    let result = query_integrity_level_with(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

fn query_integrity_level_with(handle: HANDLE) -> Option<String> {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel,
    };

    let mut token = HANDLE::default();
    let ok = unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) };
    if ok.is_err() || token.is_invalid() {
        return None;
    }
    let result = (|| {
        let mut size = 0u32;
        let rc = unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut size) };
        if rc.is_err() || size == 0 || size > 4096 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr().cast()),
                size,
                &mut size,
            )
        };
        if rc.is_err() {
            return None;
        }
        // TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { SID*, Attributes } };
        // the SID (in our buffer) exposes the last sub-authority as the label.
        let label = unsafe { &*(buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
        let sid = label.Label.Sid.0;
        if sid.is_null() {
            return None;
        }
        let count = unsafe { *sid.cast::<u8>().add(1) } as usize; // SID.SubAuthorityCount
        if count == 0 {
            return None;
        }
        let subauth_off = 8 + 4 * (count - 1);
        if subauth_off + 4 > size as usize {
            return None;
        }
        let value = unsafe { (sid.cast::<u8>().add(subauth_off) as *const u32).read_unaligned() };
        Some(match value {
            0x0000 => "Untrusted".to_string(),
            0x1000 => "Low".to_string(),
            0x2000 => "Medium".to_string(),
            0x3000 => "High".to_string(),
            0x4000 => "System".to_string(),
            _ => value.to_string(),
        })
    })();
    let _ = unsafe { CloseHandle(token) };
    result
}

/// Logon ID of the process token (`TokenStatistics.AuthenticationId`) in
/// Sysmon's `0x…` form. `None` on failure.
pub fn query_logon_id(pid: u32) -> Option<String> {
    let handle = open_process(pid, PROCESS_QUERY_INFORMATION)?;
    let result = query_logon_id_with(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

fn query_logon_id_with(handle: HANDLE) -> Option<String> {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics,
    };

    let mut token = HANDLE::default();
    let ok = unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) };
    if ok.is_err() || token.is_invalid() {
        return None;
    }
    let result = (|| {
        let mut size = 0u32;
        let rc = unsafe { GetTokenInformation(token, TokenStatistics, None, 0, &mut size) };
        if rc.is_err() || size == 0 || size > 512 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetTokenInformation(
                token,
                TokenStatistics,
                Some(buf.as_mut_ptr().cast()),
                size,
                &mut size,
            )
        };
        if rc.is_err() {
            return None;
        }
        let stats = unsafe { &*(buf.as_ptr().cast::<TOKEN_STATISTICS>()) };
        let auth = stats.AuthenticationId;
        let value = ((auth.HighPart as u64) << 32) | u64::from(auth.LowPart);
        Some(format!("0x{value:x}"))
    })();
    let _ = unsafe { CloseHandle(token) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_quad_round_trip() {
        // 2024-01-01T00:00:00Z = 133485408000000000 (100ns since 1601).
        let ft = FILETIME {
            dwLowDateTime: 0x8000_0000,
            dwHighDateTime: 0x01d9_5dcf,
        };
        let quad = filetime_to_quad(&ft);
        assert!(quad > FILETIME_TO_UNIX_EPOCH_100NS);
        let unix = (quad - FILETIME_TO_UNIX_EPOCH_100NS) / 10_000_000;
        assert_eq!(unix, 1_704_067_200);
    }
}
