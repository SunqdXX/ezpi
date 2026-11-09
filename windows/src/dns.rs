//! The local DNS server. While EzPi is on, Windows sends every query here (NRPT rule for ".").
//!
//! Most names are simply forwarded to the PC's normal DNS servers and the answer is passed back
//! unchanged, so nothing about them changes (same CDN servers, same speed). A name counts as
//! blocked when the ISP answers it with its block-page address (learned at start by asking for
//! names known to be blocked) or refuses to answer it while DoH can, or when it is on the
//! built-in list. Blocked names are answered with EzPi's loopback address, so the app connects
//! to the SNI proxy, which reaches the real server.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    doh::{Doh, build_query, parse_a},
    log, targets,
};

const VERDICT_TTL: Duration = Duration::from_secs(600);

/// Called when a new blocked name is seen (the window refreshes its counter).
pub static ON_NEW: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Name of the question in a query, its type, and the offset just after the question.
pub fn question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut o = 12;
    let mut name = String::new();
    loop {
        let l = usize::from(*q.get(o)?);
        o += 1;
        if l == 0 {
            break;
        }
        if l > 63 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(q.get(o..o + l)?).ok()?);
        o += l;
    }
    let qtype = u16::from_be_bytes([*q.get(o)?, *q.get(o + 1)?]);
    Some((name.to_ascii_lowercase(), qtype, o + 4))
}

/// Reply for a blocked name: A → `ip`; any other type → no records (so apps use IPv4).
pub fn answer(q: &[u8], end: usize, qtype: u16, ip: Ipv4Addr) -> Vec<u8> {
    let mut r = Vec::with_capacity(end + 16);
    r.extend_from_slice(&q[..2]);
    r.extend([0x81 | (q[2] & 0x01), 0x80]);
    r.extend([0, 1, 0, u8::from(qtype == 1), 0, 0, 0, 0]);
    r.extend_from_slice(&q[12..end]);
    if qtype == 1 {
        r.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
        r.extend(ip.octets());
    }
    r
}

fn rcode(reply: &[u8]) -> u8 {
    reply.get(3).map_or(2, |b| b & 0x0F)
}

pub struct Resolver {
    upstream: Vec<SocketAddr>,
    doh: Arc<Doh>,
    /// Addresses the ISP answers with instead of the real ones (its block page).
    block_ips: Mutex<HashSet<Ipv4Addr>>,
    verdicts: Mutex<HashMap<String, (bool, Instant)>>,
    /// Blocked names seen this session (shown in the window).
    pub opened: Mutex<HashSet<String>>,
}

impl Resolver {
    pub fn new(upstream: Vec<SocketAddr>, doh: Arc<Doh>) -> Self {
        Self {
            upstream,
            doh,
            // Türk Telekom's block page; others are learned by `learn`.
            block_ips: Mutex::new(HashSet::from([Ipv4Addr::new(195, 175, 254, 2)])),
            verdicts: Mutex::new(HashMap::new()),
            opened: Mutex::new(HashSet::new()),
        }
    }

    /// Ask the normal DNS servers; first answer wins.
    pub fn forward(&self, query: &[u8]) -> Option<Vec<u8>> {
        for up in &self.upstream {
            let bind: SocketAddr = if up.is_ipv4() {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let Ok(s) = UdpSocket::bind(bind) else {
                continue;
            };
            let _ = s.set_read_timeout(Some(Duration::from_millis(2500)));
            if s.send_to(query, up).is_err() {
                continue;
            }
            let mut buf = [0u8; 4096];
            if let Ok((n, from)) = s.recv_from(&mut buf)
                && from.ip() == up.ip()
                && n >= 12
                && buf[..2] == query[..2]
            {
                return Some(buf[..n].to_vec());
            }
        }
        None
    }

    /// The ISP's A answer for `host`, through the normal servers.
    fn isp_a(&self, host: &str) -> Option<(u8, Vec<Ipv4Addr>)> {
        let id = (std::process::id() as u16) ^ (host.len() as u16).rotate_left(7);
        let reply = self.forward(&build_query(id, host, 1)?)?;
        let ips = parse_a(&reply).map(|(ips, _)| ips).unwrap_or_default();
        Some((rcode(&reply), ips))
    }

    /// Learn the ISP's block-page addresses from names known to be blocked in Turkey.
    pub fn learn(&self) {
        for host in ["discord.com", "www.roblox.com", "discordapp.com"] {
            let (Some((_, isp)), Ok(real)) = (self.isp_a(host), self.doh.resolve(host)) else {
                continue;
            };
            if !isp.is_empty() && isp.iter().all(|ip| !real.contains(ip)) {
                let mut b = self.block_ips.lock().unwrap();
                for ip in isp {
                    if b.insert(ip) {
                        log::line(&format!("ISP block page address: {ip}"));
                    }
                }
            }
        }
    }

    fn judge(&self, host: &str, isp: Option<(u8, Vec<Ipv4Addr>)>) -> bool {
        if targets::matches(host) {
            return true;
        }
        match isp {
            Some((0, ips)) if !ips.is_empty() => {
                let b = self.block_ips.lock().unwrap();
                ips.iter().any(|ip| b.contains(ip))
            }
            // NXDOMAIN / REFUSED / SERVFAIL for a name that really exists: censored.
            Some((rc, _)) if rc == 2 || rc == 3 || rc == 5 => {
                self.doh.resolve(host).is_ok_and(|r| !r.is_empty())
            }
            _ => false,
        }
    }

    fn cached(&self, host: &str) -> Option<bool> {
        let v = self.verdicts.lock().unwrap();
        v.get(host)
            .filter(|(_, t)| t.elapsed() < VERDICT_TTL)
            .map(|(b, _)| *b)
    }

    fn remember(&self, host: &str, blocked: bool) {
        self.verdicts
            .lock()
            .unwrap()
            .insert(host.to_string(), (blocked, Instant::now()));
        if blocked && self.opened.lock().unwrap().insert(host.to_string()) {
            log::line(&format!("unblocking {host}"));
            if let Some(f) = ON_NEW.get() {
                f();
            }
        }
    }

    /// The reply to send for one query.
    fn reply(&self, q: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
        let (name, qtype, end) = question(q)?;
        // Only real hostnames can be blocked; reverse lookups, local names etc. pass through.
        let checkable = name.contains('.') && !name.ends_with(".arpa") && !name.ends_with(".local");
        if checkable {
            let blocked = match self.cached(&name) {
                Some(b) => b,
                None if targets::matches(&name) => true,
                None if qtype == 1 => {
                    let reply = self.forward(q)?;
                    let ips = parse_a(&reply).map(|(i, _)| i).unwrap_or_default();
                    let b = self.judge(&name, Some((rcode(&reply), ips)));
                    self.remember(&name, b);
                    if !b {
                        return Some(reply);
                    }
                    true
                }
                None => {
                    let b = self.judge(&name, self.isp_a(&name));
                    self.remember(&name, b);
                    b
                }
            };
            if blocked {
                self.remember(&name, true);
                return Some(answer(q, end, qtype, ip));
            }
        }
        self.forward(q)
    }
}

/// Serve until `stop` is set. Each query is handled on its own small thread.
pub fn serve(sock: UdpSocket, ip: Ipv4Addr, r: Arc<Resolver>, stop: Arc<AtomicBool>) {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
    let mut buf = [0u8; 1500];
    while !stop.load(Ordering::Relaxed) {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let (q, r) = (buf[..n].to_vec(), r.clone());
        let Ok(sock) = sock.try_clone() else { continue };
        let _ = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                if let Some(reply) = r.reply(&q, ip) {
                    let _ = sock.send_to(&reply, from);
                }
            });
    }
}

/// The PC's normal DNS servers (from the network adapters that are up), EzPi's own excluded.
pub fn system_servers(own: Ipv4Addr) -> Vec<SocketAddr> {
    #![allow(unsafe_code)]
    use windows::Win32::{
        NetworkManagement::IpHelper::{
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
            IP_ADAPTER_ADDRESSES_LH,
        },
        NetworkManagement::Ndis::IfOperStatusUp,
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
    };
    let mut out = Vec::new();
    let mut len = 32 * 1024u32;
    let mut buf = vec![0u64; len as usize / 8];
    // SAFETY: GetAdaptersAddresses fills our u64-aligned buffer with a linked list that stays
    // inside it; socket addresses are read according to their family.
    unsafe {
        let rc = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            None,
            Some(buf.as_mut_ptr().cast()),
            &mut len,
        );
        if rc != 0 {
            return out;
        }
        let mut a = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !a.is_null() {
            if (*a).OperStatus == IfOperStatusUp {
                let mut d = (*a).FirstDnsServerAddress;
                while !d.is_null() {
                    let sa = (*d).Address.lpSockaddr;
                    if !sa.is_null() {
                        let addr = match (*sa).sa_family {
                            f if f == AF_INET => {
                                let s = &*sa.cast::<SOCKADDR_IN>();
                                Some(IpAddr::from(Ipv4Addr::from(u32::from_be(
                                    s.sin_addr.S_un.S_addr,
                                ))))
                            }
                            f if f == AF_INET6 => {
                                let s = &*sa.cast::<SOCKADDR_IN6>();
                                let ip = std::net::Ipv6Addr::from(s.sin6_addr.u.Byte);
                                // site-local resolver addresses need a scope id; skip them
                                (!ip.is_unicast_link_local()).then_some(IpAddr::from(ip))
                            }
                            _ => None,
                        };
                        if let Some(ip) = addr
                            && ip != IpAddr::from(own)
                            && !ip.is_unspecified()
                            && !(ip.is_loopback() && ip != IpAddr::from(Ipv4Addr::LOCALHOST))
                        {
                            let s = SocketAddr::new(ip, 53);
                            if !out.contains(&s) {
                                out.push(s);
                            }
                        }
                    }
                    d = (*d).Next;
                }
            }
            a = (*a).Next;
        }
    }
    // IPv4 servers first: they are the ones the ISP's router hands out.
    out.sort_by_key(|s| !s.is_ipv4());
    if out.is_empty() {
        out.push(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_blocked_names_with_loopback_and_no_aaaa() {
        let ip = Ipv4Addr::new(127, 65, 80, 1);
        let q = build_query(7, "Thumbnails.Roblox.com", 1).unwrap();
        let (name, t, end) = question(&q).unwrap();
        assert_eq!((name.as_str(), t), ("thumbnails.roblox.com", 1));
        let (ips, _) = parse_a(&answer(&q, end, t, ip)).unwrap();
        assert_eq!(ips, vec![ip]);
        let q6 = build_query(8, "discord.com", 28).unwrap();
        let (_, t, end) = question(&q6).unwrap();
        let r = answer(&q6, end, t, ip);
        assert_eq!(&r[6..8], &[0, 0]);
        assert_eq!(r[3] & 0x0F, 0);
    }

    #[test]
    fn judges_block_page_and_lists() {
        let r = Resolver::new(vec![], Arc::new(Doh::new().unwrap()));
        assert!(r.judge("www.roblox.com", None));
        assert!(r.judge(
            "x.example",
            Some((0, vec![Ipv4Addr::new(195, 175, 254, 2)]))
        ));
        assert!(!r.judge(
            "x.example",
            Some((0, vec![Ipv4Addr::new(93, 184, 216, 34)]))
        ));
        assert!(!r.judge("x.example", None));
    }
}
