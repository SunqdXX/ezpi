//! The SNI proxy on EzPi's loopback address. Apps reach it because the local DNS answers the
//! target names with that address. TLS stays end to end (EzPi never decrypts anything): it reads
//! the ClientHello only to learn the hostname, resolves the real address over DoH, and sends
//! the ClientHello to the real server split into TLS records, which the DPI can't read.
//! Port 80 is forwarded by the Host header.

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{
    doh::Doh,
    tls::{self, STRATEGIES, Strategy},
};

const STACK: usize = 96 * 1024;
const CONNECT: Duration = Duration::from_secs(6);
/// How long to wait for the server's first reply before trying the next strategy.
const PROBE: Duration = Duration::from_millis(2500);
const IDLE: Duration = Duration::from_secs(300);

pub struct Proxy {
    pub doh: Arc<Doh>,
    /// The strategy that last worked per hostname, tried first next time.
    learned: Mutex<HashMap<String, Strategy>>,
    pub open: AtomicUsize,
    pub log: fn(&str),
}

impl Proxy {
    pub fn new(doh: Arc<Doh>, log: fn(&str)) -> Self {
        Self {
            doh,
            learned: Mutex::new(HashMap::new()),
            open: AtomicUsize::new(0),
            log,
        }
    }

    fn order(&self, host: &str) -> Vec<Strategy> {
        let mut v = STRATEGIES.to_vec();
        if let Some(s) = self.learned.lock().unwrap().get(host)
            && let Some(i) = v.iter().position(|x| x == s)
        {
            let s = v.remove(i);
            v.insert(0, s);
        }
        v
    }

    fn dial(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let ips = self.doh.resolve(host)?;
        let mut err = io::Error::other("no address");
        for ip in ips.iter().take(3) {
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            match TcpStream::connect_timeout(&SocketAddr::from((*ip, port)), CONNECT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => err = e,
            }
        }
        Err(err)
    }

    /// Connect to `host` and get `hello` through with the first strategy the server answers.
    /// Returns the upstream and the server's first bytes.
    pub fn open_tls(&self, host: &str, hello: &[u8]) -> io::Result<(TcpStream, Vec<u8>)> {
        let order = self.order(host);
        let mut err = io::Error::other("no strategy got a reply");
        for (i, s) in order.iter().enumerate() {
            let mut up = match self.dial(host, 443) {
                Ok(u) => u,
                Err(e) => {
                    err = e;
                    continue;
                }
            };
            if let Err(e) = s.send(&mut up, hello) {
                err = e;
                continue;
            }
            let _ = up.set_read_timeout(Some(PROBE));
            let mut buf = vec![0u8; 16 * 1024];
            match up.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let _ = up.set_read_timeout(None);
                    buf.truncate(n);
                    if i > 0 {
                        (self.log)(&format!("{host}: {} works", s.name()));
                    }
                    self.learned.lock().unwrap().insert(host.to_string(), *s);
                    return Ok((up, buf));
                }
                Ok(_) => err = io::Error::other("server closed the connection"),
                Err(e) => err = e,
            }
        }
        Err(err)
    }
}

/// Read one complete TLS record (the ClientHello) from the app.
fn read_hello(c: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; tls::REC_HEADER];
    c.read_exact(&mut hdr)?;
    let len = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    if hdr[0] != tls::REC_HANDSHAKE || len == 0 || len > tls::MAX_RECORD {
        return Err(io::Error::other("not a TLS ClientHello"));
    }
    let mut rec = vec![0u8; tls::REC_HEADER + len];
    rec[..tls::REC_HEADER].copy_from_slice(&hdr);
    c.read_exact(&mut rec[tls::REC_HEADER..])?;
    Ok(rec)
}

/// Copy both ways until either side is done or idle for [`IDLE`].
fn splice(a: TcpStream, b: TcpStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let t = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || pipe(a2, b2));
    pipe(b, a);
    if let Ok(t) = t {
        let _ = t.join();
    }
}

fn pipe(from: TcpStream, to: TcpStream) {
    pipe_with(from, to, false)
}

/// The ISP also blocks plain HTTP by its `Host` header; servers read header names in any case,
/// the DPI only matches `Host`. Same length, so nothing else changes.
fn mask_host(b: &mut [u8]) {
    let mut i = 0;
    while i + 6 <= b.len() {
        if b[i] == b'\n' && b[i + 1..i + 6].eq_ignore_ascii_case(b"host:") {
            b[i + 1..i + 6].copy_from_slice(b"hoSt:");
            i += 6;
        } else {
            i += 1;
        }
    }
}

fn pipe_with(mut from: TcpStream, mut to: TcpStream, http: bool) {
    let _ = from.set_read_timeout(Some(IDLE));
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if http {
                    mask_host(&mut buf[..n]);
                }
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
    let _ = from.shutdown(Shutdown::Read);
}

fn handle_tls(p: &Proxy, mut c: TcpStream) -> io::Result<()> {
    let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
    let hello = read_hello(&mut c)?;
    let host = tls::sni(&hello).ok_or_else(|| io::Error::other("ClientHello without a name"))?;
    let (up, early) = p.open_tls(&host, &hello).map_err(|e| {
        (p.log)(&format!("{host}: {e}"));
        e
    })?;
    let _ = c.set_read_timeout(None);
    c.write_all(&early)?;
    splice(c, up);
    Ok(())
}

fn handle_http(p: &Proxy, mut c: TcpStream) -> io::Result<()> {
    let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::with_capacity(1024);
    let mut b = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = c.read(&mut b)?;
        if n == 0 || head.len() > 16 * 1024 {
            return Err(io::Error::other("bad HTTP request"));
        }
        head.extend_from_slice(&b[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let host = text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("host")
                .then(|| v.trim().to_string())
        })
        .ok_or_else(|| io::Error::other("no Host header"))?;
    let host = host
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut up = p.dial(&host, 80)?;
    mask_host(&mut head);
    up.write_all(&head)?;
    let _ = c.set_read_timeout(None);
    // app -> server keeps masking later requests on the same connection
    let (Ok(c2), Ok(up2)) = (c.try_clone(), up.try_clone()) else {
        return Ok(());
    };
    let t = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || pipe_with(c2, up2, true));
    pipe(up, c);
    if let Ok(t) = t {
        let _ = t.join();
    }
    Ok(())
}

/// Accept on `l` until `stop`; each connection gets its own small thread.
pub fn serve(p: Arc<Proxy>, l: TcpListener, tls: bool, stop: Arc<AtomicBool>) {
    let _ = l.set_nonblocking(true);
    while !stop.load(Ordering::Relaxed) {
        match l.accept() {
            Ok((c, _)) => {
                let _ = c.set_nonblocking(false);
                let _ = c.set_nodelay(true);
                let p = p.clone();
                let _ = std::thread::Builder::new()
                    .stack_size(STACK)
                    .spawn(move || {
                        p.open.fetch_add(1, Ordering::Relaxed);
                        let _ = if tls {
                            handle_tls(&p, c)
                        } else {
                            handle_http(&p, c)
                        };
                        p.open.fetch_sub(1, Ordering::Relaxed);
                    });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Live check: can `host` be reached through the bypass right now?
pub fn check(p: &Proxy, host: &str) -> io::Result<()> {
    p.open_tls(host, &probe_hello(host)).map(|_| ())
}

/// A small but real TLS 1.3 ClientHello (X25519, AES-128-GCM) for the live check.
fn probe_hello(host: &str) -> Vec<u8> {
    let h = host.as_bytes();
    let u16b = |n: usize| (n as u16).to_be_bytes();
    let mut sni = vec![0u8];
    sni.extend(u16b(h.len()));
    sni.extend(h);
    let mut list = u16b(sni.len()).to_vec();
    list.extend(&sni);
    let mut ext = vec![0, 0];
    ext.extend(u16b(list.len()));
    ext.extend(&list);
    ext.extend([0, 0x0a, 0, 4, 0, 2, 0, 0x1d]); // groups: x25519
    ext.extend([0, 0x0d, 0, 6, 0, 4, 4, 3, 8, 4]); // signature algorithms
    ext.extend([0, 0x2b, 0, 3, 2, 3, 4]); // TLS 1.3
    ext.extend([0, 0x33, 0, 38, 0, 36, 0, 0x1d, 0, 32]);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    ext.extend((0..32).map(|i| (seed.rotate_left(i) as u8) | 1));
    let mut body = vec![3, 3];
    body.extend((0..32).map(|i| seed.rotate_right(i) as u8));
    body.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend(u16b(ext.len()));
    body.extend(&ext);
    let mut hs = vec![tls::HS_CLIENT_HELLO, 0];
    hs.extend(u16b(body.len()));
    hs.extend(&body);
    let mut rec = vec![tls::REC_HANDSHAKE, 3, 1];
    rec.extend(u16b(hs.len()));
    rec.extend(hs);
    rec
}

pub const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 65, 80, 1);

#[cfg(test)]
mod tests {
    #[test]
    fn host_header_is_masked_in_place() {
        let mut b = b"GET / HTTP/1.1\r\nHOST: a.roblox.com\r\nX-Host: y\r\n\r\n".to_vec();
        let n = b.len();
        super::mask_host(&mut b);
        assert_eq!(b.len(), n);
        assert_eq!(
            &b,
            b"GET / HTTP/1.1\r\nhoSt: a.roblox.com\r\nX-Host: y\r\n\r\n"
        );
    }
}
