//! The Name Resolution Policy Table rule that sends DNS queries to EzPi's DNS server while it is
//! on. It's a standard Windows feature (Add-DnsClientNrptRule writes the same key). Needs
//! administrator rights.
//!
//! The rule lists the PC's normal DNS servers after EzPi's own, so if EzPi is not running (a
//! crash, power loss), Windows falls back to normal DNS and nothing breaks.
#![allow(unsafe_code)]

use std::io;

use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR},
        NetworkManagement::Dns::{
            DNS_QUERY_BYPASS_CACHE, DNS_QUERY_NO_HOSTS_FILE, DNS_RECORDA, DNS_TYPE_A, DnsFree,
            DnsFreeRecordList, DnsQuery_W,
        },
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_MULTI_SZ,
                REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
                RegSetValueExW,
            },
        },
    },
    core::{HSTRING, PCWSTR, s, w},
};

use crate::proxy::LOOPBACK;

const KEY: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\EzPi";

fn check(rc: WIN32_ERROR) -> io::Result<()> {
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc.0 as i32))
    }
}

fn wide_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Add (or refresh) the rule.
/// `fallback`: the PC's normal DNS servers, used by Windows if EzPi stops answering.
pub fn install(fallback: &[std::net::SocketAddr]) -> io::Result<()> {
    // "." = every name.
    let names: Vec<u8> = ".\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut servers = LOOPBACK.to_string();
    for s in fallback.iter().filter(|s| s.is_ipv4()).take(2) {
        servers.push(';');
        servers.push_str(&s.ip().to_string());
    }
    // SAFETY: registry calls with valid buffers; the key handle is closed below.
    unsafe {
        let mut h = HKEY::default();
        check(RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(KEY),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut h,
            None,
        ))?;
        let set = |name: PCWSTR, kind, data: &[u8]| {
            check(RegSetValueExW(h, name, None, kind, Some(data)))
        };
        let r = (|| {
            set(w!("Version"), REG_DWORD, &2u32.to_le_bytes())?;
            set(w!("Name"), REG_MULTI_SZ, &names)?;
            set(w!("ConfigOptions"), REG_DWORD, &8u32.to_le_bytes())?;
            set(w!("GenericDNSServers"), REG_SZ, &wide_bytes(&servers))?;
            set(w!("IPSECCARestriction"), REG_SZ, &wide_bytes(""))?;
            set(
                w!("Comment"),
                REG_SZ,
                &wide_bytes("EzPi: blocked names go to EzPi"),
            )?;
            set(w!("DisplayName"), REG_SZ, &wide_bytes("EzPi"))
        })();
        let _ = RegCloseKey(h);
        r?;
    }
    flush();
    Ok(())
}

/// Remove the rule (fine if it isn't there).
pub fn remove() -> io::Result<()> {
    // SAFETY: plain registry call.
    let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, &HSTRING::from(KEY)) };
    flush();
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(rc)
}

/// Clear Windows' DNS cache, so poisoned answers already cached are forgotten.
fn flush() {
    // SAFETY: DnsFlushResolverCache takes no arguments and returns a BOOL; dnsapi.dll is a
    // system library that stays loaded.
    unsafe {
        if let Ok(lib) = LoadLibraryW(w!("dnsapi.dll"))
            && let Some(f) = GetProcAddress(lib, s!("DnsFlushResolverCache"))
        {
            let f: unsafe extern "system" fn() -> i32 = std::mem::transmute(f);
            f();
        }
    }
}

/// What Windows itself answers for `host` (bypassing its cache), to check the rule works.
pub fn system_lookup(host: &str) -> Option<std::net::Ipv4Addr> {
    let mut rec: *mut DNS_RECORDA = std::ptr::null_mut();
    // SAFETY: DnsQuery_W allocates the record list, freed with DnsFree below.
    unsafe {
        let rc = DnsQuery_W(
            &HSTRING::from(host),
            DNS_TYPE_A,
            DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
            None,
            &mut rec,
            None,
        );
        if rc != ERROR_SUCCESS || rec.is_null() {
            return None;
        }
        let mut out = None;
        let mut p = rec;
        while !p.is_null() {
            if (*p).wType == DNS_TYPE_A.0 {
                let ip = (*p).Data.A.IpAddress;
                out = Some(std::net::Ipv4Addr::from(u32::from_be(ip)));
                break;
            }
            p = (*p).pNext;
        }
        DnsFree(Some(rec.cast()), DnsFreeRecordList);
        out
    }
}

/// Whether the rule is present (left over after a crash, or ours).
pub fn present() -> bool {
    use windows::Win32::System::Registry::{KEY_READ, RegOpenKeyExW};
    let mut h = HKEY::default();
    // SAFETY: plain registry calls; the handle is closed if opened.
    unsafe {
        let ok = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(KEY),
            None,
            KEY_READ,
            &mut h,
        ) == ERROR_SUCCESS;
        if ok {
            let _ = RegCloseKey(h);
        }
        ok
    }
}
