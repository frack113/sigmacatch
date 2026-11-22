// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Authenticode facts for the image events (EID 6/7): `Signed`, `Signature`
//! and `SignatureStatus`.
//!
//! `WinVerifyTrust` answers "is this file signed by a chain the machine
//! trusts"; the signer's display name is not part of its answer, so it is read
//! from the embedded PKCS#7 signature (`CryptQueryObject` → the first signer →
//! the matching certificate → `CertGetNameStringW`).
//!
//! The status values are Sysmon's three: `Valid`, `Unavailable` (no signature
//! that could be read) and `Errored` (a signature exists but does not verify).
//! An expired or untrusted chain is therefore `Errored`, with the signer name
//! still reported.

use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{
    CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_ENCODING_TYPE,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
    CMSG_SIGNER_INFO_PARAM, CRYPT_INTEGER_BLOB, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
    HCERTSTORE, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::{GUID, PCWSTR};

/// `TRUST_E_NOSIGNATURE`: the file carries no signature at all.
const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;

/// What an image's signature says, as Sysmon spells it.
#[derive(Debug, Clone)]
pub struct Signature {
    /// True when a signature is present, whatever its chain says.
    pub signed: bool,
    /// Signer display name (`Microsoft Windows`), when it could be read.
    pub name: Option<String>,
    /// `Valid`, `Unavailable` or `Errored`.
    pub status: &'static str,
}

/// Read the signature of the file at `path`.
///
/// `None` when the file cannot be inspected at all (missing, locked); callers
/// leave the three fields out rather than reporting "unsigned".
pub fn of_file(path: &str) -> Option<Signature> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: core::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: core::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: core::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file` outlive the call and describe themselves.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            (&raw mut data).cast::<core::ffi::c_void>(),
        )
    };
    let name = signer_name(&wide);

    // Release the state the verify call allocated.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closing the state acquired by the verify call above.
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &raw mut action,
            (&raw mut data).cast::<core::ffi::c_void>(),
        )
    };

    // A great many Windows binaries carry no embedded signature at all: they
    // are signed through a security catalog. Without this second pass they
    // would be reported as unsigned, which is exactly what the "unsigned
    // binary" rules look for.
    let catalog_status = if status == 0 {
        None
    } else {
        verify_catalog(&wide)
    };
    if catalog_status == Some(0) {
        return Some(Signature {
            signed: true,
            name,
            status: "Valid",
        });
    }

    let signature = match status {
        0 => Signature {
            signed: true,
            name,
            status: "Valid",
        },
        TRUST_E_NOSIGNATURE if name.is_none() => Signature {
            signed: false,
            name: None,
            status: "Unavailable",
        },
        _ => match name {
            Some(name) => Signature {
                signed: true,
                name: Some(name),
                status: "Errored",
            },
            None => Signature {
                signed: false,
                name: None,
                status: "Unavailable",
            },
        },
    };
    Some(signature)
}

/// Verify `path` against the security catalogs, for binaries without an
/// embedded signature. Returns the `WinVerifyTrust` status.
fn verify_catalog(wide: &[u16]) -> Option<i32> {
    let mut admin: isize = 0;
    let algorithm: Vec<u16> = "SHA256".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: the algorithm string is NUL-terminated and `admin` is local.
    unsafe {
        CryptCATAdminAcquireContext2(&raw mut admin, None, PCWSTR(algorithm.as_ptr()), None, None)
    }
    .ok()?;

    // The member hash is computed over the file, so it has to be open.
    // SAFETY: `wide` is NUL-terminated and valid for the call.
    let file = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    };
    let Ok(file) = file else {
        // SAFETY: `admin` was acquired above.
        let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };
        return None;
    };

    let mut hash_len = 0u32;
    // SAFETY: the handle is open; the first call only asks for the size.
    let sized =
        unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, file, &raw mut hash_len, None, None) };
    let mut hash = vec![0u8; hash_len as usize];
    let hashed = sized.ok().is_some()
        && !hash.is_empty()
        // SAFETY: `hash` is sized by the call above.
        && unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file,
                &raw mut hash_len,
                Some(hash.as_mut_ptr()),
                None,
            )
        }
        .is_ok();
    // SAFETY: the handle came from `CreateFileW` exactly once.
    let _ = unsafe { CloseHandle(file) };
    if !hashed {
        // SAFETY: `admin` was acquired above.
        let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };
        return None;
    }
    hash.truncate(hash_len as usize);

    // SAFETY: `admin` is live and `hash` is the member hash of this file.
    let catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
    if catalog == 0 {
        // SAFETY: `admin` was acquired above.
        let _ = unsafe { CryptCATAdminReleaseContext(admin, 0) };
        return None;
    }

    let mut info = CATALOG_INFO {
        cbStruct: core::mem::size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `catalog` is a live catalog context and `info` is sized.
    let catalog_path = unsafe { CryptCATCatalogInfoFromContext(catalog, &raw mut info, 0) }
        .ok()
        .map(|()| info.wszCatalogFile);

    // The member tag is the SHA256 of the file, uppercase hex.
    let tag: Vec<u16> = hash
        .iter()
        .flat_map(|byte| format!("{byte:02X}").encode_utf16().collect::<Vec<_>>())
        .chain(std::iter::once(0))
        .collect();

    let status = match catalog_path {
        None => None,
        Some(catalog_path) => {
            let mut parameters = WINTRUST_CATALOG_INFO {
                cbStruct: core::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: PCWSTR(catalog_path.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wide.as_ptr()),
                hMemberFile: Default::default(),
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash.len() as u32,
                pcCatalogContext: catalog as *mut _,
                hCatAdmin: admin,
            };
            let mut data = WINTRUST_DATA {
                cbStruct: core::mem::size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                Anonymous: WINTRUST_DATA_0 {
                    pCatalog: &raw mut parameters,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                ..Default::default()
            };
            let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            // SAFETY: every structure outlives the call and describes itself.
            let status = unsafe {
                WinVerifyTrust(
                    HWND::default(),
                    &raw mut action,
                    (&raw mut data).cast::<core::ffi::c_void>(),
                )
            };
            Some(status)
        }
    };

    // SAFETY: both contexts were acquired above, released exactly once.
    unsafe {
        let _ = CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        let _ = CryptCATAdminReleaseContext(admin, 0);
    }
    status
}

/// Signer display name, from the embedded PKCS#7 signature.
fn signer_name(wide: &[u16]) -> Option<String> {
    let mut encoding = CERT_QUERY_ENCODING_TYPE(0);
    let mut store = HCERTSTORE::default();
    let mut message: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: the path is NUL-terminated and the out-parameters are local.
    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&raw mut encoding),
            None,
            None,
            Some(&raw mut store),
            Some(&raw mut message),
            None,
        )
    }
    .ok()?;

    let name = if message.is_null() {
        None
    } else {
        // SAFETY: `message` is a live CMSG handle from the call above.
        unsafe { signer_name_from_message(message, store, encoding) }
    };

    // SAFETY: both handles were opened above, each closed exactly once.
    unsafe {
        if !message.is_null() {
            let _ = CryptMsgClose(Some(message));
        }
        let _ = windows::Win32::Security::Cryptography::CertCloseStore(Some(store), 0);
    }
    name
}

/// First signer of `message`, resolved to its certificate's display name.
unsafe fn signer_name_from_message(
    message: *mut core::ffi::c_void,
    store: HCERTSTORE,
    encoding: CERT_QUERY_ENCODING_TYPE,
) -> Option<String> {
    let mut size = 0u32;
    // SAFETY: the first call only asks for the size.
    unsafe { CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &raw mut size) }.ok()?;
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` is sized for `size` bytes by the call above.
    unsafe {
        CryptMsgGetParam(
            message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buffer.as_mut_ptr().cast()),
            &raw mut size,
        )
    }
    .ok()?;
    if buffer.len() < core::mem::size_of::<CMSG_SIGNER_INFO>() {
        return None;
    }
    // SAFETY: the provider filled a CMSG_SIGNER_INFO into `buffer`.
    let signer = unsafe { &*(buffer.as_ptr().cast::<CMSG_SIGNER_INFO>()) };
    let certificate_info = windows::Win32::Security::Cryptography::CERT_INFO {
        Issuer: CRYPT_INTEGER_BLOB {
            cbData: signer.Issuer.cbData,
            pbData: signer.Issuer.pbData,
        },
        SerialNumber: CRYPT_INTEGER_BLOB {
            cbData: signer.SerialNumber.cbData,
            pbData: signer.SerialNumber.pbData,
        },
        ..Default::default()
    };
    // SAFETY: the store is live and the search structure outlives the call.
    let certificate = unsafe {
        windows::Win32::Security::Cryptography::CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | encoding,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some((&raw const certificate_info).cast()),
            None,
        )
    };
    if certificate.is_null() {
        return None;
    }
    let mut name = vec![0u16; 512];
    // SAFETY: the certificate is live and `name` describes itself.
    let len = unsafe {
        windows::Win32::Security::Cryptography::CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name),
        )
    } as usize;
    // SAFETY: the context came from `CertFindCertificateInStore` exactly once.
    unsafe {
        let _ =
            windows::Win32::Security::Cryptography::CertFreeCertificateContext(Some(certificate));
    }
    if len <= 1 || len > name.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&name[..len - 1]))
}
