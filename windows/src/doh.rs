//! DNS over HTTPS through WinHTTP (part of Windows, no TLS library to ship).
//!
//! The ISP rewrites plain DNS for blocked names, even when it is sent to 1.1.1.1. DoH to the
//! resolvers' IP addresses carries no hostname to block, and the answers are the real ones.
#![allow(unsafe_code)]

use std::{
    collections::HashMap,
    ffi::c_void,
    io,
    net::Ipv4Addr,
    sync::Mutex,
    time::{Duration, Instant},
};

use windows::{
    Win32::Networking::WinHttp::*,
    core::{PCWSTR, w},
};

const SERVERS: [PCWSTR; 3] = [w!("1.1.1.1"), w!("8.8.8.8"), w!("9.9.9.9")];

struct Handle(*mut c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a WinHTTP handle we own, closed once.
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn last() -> io::Error {
    io::Error::last_os_error()
}

pub struct Doh {
    session: Handle,
    cache: Mutex<HashMap<String, (Vec<Ipv4Addr>, Instant)>>,
}

// WinHTTP session handles may be used from any thread.
unsafe impl Send for Doh {}
unsafe impl Sync for Doh {}

impl Doh {
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain WinHTTP calls; the session is closed by `Handle`.
        unsafe {
            let s = WinHttpOpen(
                w!("EzPi"),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            );
            if s.is_null() {
                return Err(last());
            }
            let _ = WinHttpSetTimeouts(s, 3000, 3000, 3000, 3000);
            Ok(Self {
                session: Handle(s),
                cache: Mutex::new(HashMap::new()),
            })
        }
    }

    /// Send a DNS message, return the DNS reply (first resolver that answers).
    pub fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut err = io::Error::other("no resolver answered");
        for server in SERVERS {
            match self.post(server, query) {
                Ok(r) => return Ok(r),
                Err(e) => err = e,
            }
        }
        Err(err)
    }

    fn post(&self, server: PCWSTR, query: &[u8]) -> io::Result<Vec<u8>> {
        // SAFETY: WinHTTP calls on handles we own; buffers are valid for each call.
        unsafe {
            let conn = Handle(WinHttpConnect(self.session.0, server, 443, 0));
            if conn.0.is_null() {
                return Err(last());
            }
            let req = Handle(WinHttpOpenRequest(
                conn.0,
                w!("POST"),
                w!("/dns-query"),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                WINHTTP_FLAG_SECURE,
            ));
            if req.0.is_null() {
                return Err(last());
            }
            let headers: Vec<u16> =
                "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n"
                    .encode_utf16()
                    .collect();
            WinHttpSendRequest(
                req.0,
                Some(&headers),
                Some(query.as_ptr().cast()),
                query.len() as u32,
                query.len() as u32,
                0,
            )
            .map_err(io::Error::from)?;
            WinHttpReceiveResponse(req.0, std::ptr::null_mut()).map_err(io::Error::from)?;
            let mut status = 0u32;
            let mut len = 4u32;
            let mut idx = 0u32;
            WinHttpQueryHeaders(
                req.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                PCWSTR::null(),
                Some(std::ptr::from_mut(&mut status).cast()),
                &mut len,
                &mut idx,
            )
            .map_err(io::Error::from)?;
            if status != 200 {
                return Err(io::Error::other(format!("DoH HTTP {status}")));
            }
            let mut out = Vec::with_capacity(512);
            let mut buf = [0u8; 2048];
            loop {
                let mut n = 0u32;
                WinHttpReadData(req.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n)
                    .map_err(io::Error::from)?;
                if n == 0 || out.len() > 64 * 1024 {
                    break;
                }
                out.extend_from_slice(&buf[..n as usize]);
            }
            Ok(out)
        }
    }

    /// IPv4 addresses of `host`, cached for the records' TTL (30 s to 10 min).
    pub fn resolve(&self, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        let now = Instant::now();
        if let Some((ips, exp)) = self.cache.lock().unwrap().get(host)
            && *exp > now
        {
            return Ok(ips.clone());
        }
        let q = build_query(0, host, 1).ok_or_else(|| io::Error::other("bad hostname"))?;
        let reply = self.exchange(&q)?;
        let (ips, ttl) = parse_a(&reply).ok_or_else(|| io::Error::other("bad DNS reply"))?;
        if ips.is_empty() {
            return Err(io::Error::other(format!("{host}: no address")));
        }
        let ttl = Duration::from_secs(u64::from(ttl).clamp(30, 600));
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), (ips.clone(), now + ttl));
        Ok(ips)
    }
}

/// A DNS query for `host` / `qtype` with recursion desired.
pub fn build_query(id: u16, host: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut b = Vec::with_capacity(32 + host.len());
    b.extend(id.to_be_bytes());
    b.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        b.push(label.len() as u8);
        b.extend(label.as_bytes());
    }
    b.push(0);
    b.extend(qtype.to_be_bytes());
    b.extend([0, 1]);
    Some(b)
}

/// Skip a (possibly compressed) name at `o`; returns the offset after it.
pub fn skip_name(msg: &[u8], mut o: usize) -> Option<usize> {
    loop {
        let l = *msg.get(o)?;
        if l & 0xC0 == 0xC0 {
            return Some(o + 2);
        }
        o += 1;
        if l == 0 {
            return Some(o);
        }
        o += usize::from(l);
    }
}

/// A records and the smallest TTL in a DNS reply.
pub fn parse_a(msg: &[u8]) -> Option<(Vec<Ipv4Addr>, u32)> {
    if msg.len() < 12 || msg[3] & 0x0F != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut o = 12;
    for _ in 0..qd {
        o = skip_name(msg, o)? + 4;
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        o = skip_name(msg, o)?;
        let h = msg.get(o..o + 10)?;
        let typ = u16::from_be_bytes([h[0], h[1]]);
        let t = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let len = usize::from(u16::from_be_bytes([h[8], h[9]]));
        o += 10;
        let data = msg.get(o..o + len)?;
        if typ == 1 && len == 4 {
            ips.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            ttl = ttl.min(t);
        }
        o += len;
    }
    Some((ips, if ttl == u32::MAX { 60 } else { ttl }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_answer_roundtrip() {
        let q = build_query(0x1234, "www.roblox.com", 1).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        // reply: header, question, one CNAME (pointer name), one A
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        r.extend([0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 2, 0xC0, 16]);
        r.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 128, 116, 31, 3]);
        let (ips, ttl) = parse_a(&r).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(128, 116, 31, 3)]);
        assert_eq!(ttl, 256);
        assert!(build_query(0, "a..b", 1).is_none());
    }
}
