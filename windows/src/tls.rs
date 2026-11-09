//! TLS ClientHello parsing and the split strategies (ported from daemon/engine/strategy.go).
//!
//! What works against the Turkish ISP DPI (measured): splitting the ClientHello into two TLS
//! *records* inside the hostname. Splitting only the TCP segment does not (the DPI reassembles
//! TCP). The TLS handshake transcript is unchanged, so the server accepts it.

use std::{io::Write, net::TcpStream, thread::sleep, time::Duration};

pub const REC_HANDSHAKE: u8 = 0x16;
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const REC_HEADER: usize = 5;
pub const MAX_RECORD: usize = 16384;

/// Offset and length of the SNI hostname inside a handshake message (no record header).
pub fn sni_span(hs: &[u8]) -> Option<(usize, usize)> {
    let u16at = |p: usize| -> Option<usize> {
        Some(usize::from(*hs.get(p)?) << 8 | usize::from(*hs.get(p + 1)?))
    };
    if hs.len() < 4 || hs[0] != HS_CLIENT_HELLO {
        return None;
    }
    let mut p = 4 + 2 + 32; // type+len, version, random
    p += 1 + usize::from(*hs.get(p)?); // session id
    p += 2 + u16at(p)?; // cipher suites
    p += 1 + usize::from(*hs.get(p)?); // compression
    let ext_end = (p + 2 + u16at(p)?).min(hs.len());
    p += 2;
    while p + 4 <= ext_end {
        let (etype, elen) = (u16at(p)?, u16at(p + 2)?);
        let data = p + 4;
        if data + elen > ext_end {
            return None;
        }
        if etype == 0 {
            let mut q = data + 2;
            while q + 3 <= data + elen {
                let nlen = u16at(q + 1)?;
                if hs[q] == 0 && nlen > 0 && q + 3 + nlen <= data + elen {
                    return Some((q + 3, nlen));
                }
                q += 3 + nlen;
            }
            return None;
        }
        p = data + elen;
    }
    None
}

/// The SNI hostname of a complete ClientHello record, lower-case.
pub fn sni(rec: &[u8]) -> Option<String> {
    let hs = rec.get(REC_HEADER..)?;
    let (off, len) = sni_span(hs)?;
    let name = std::str::from_utf8(&hs[off..off + len]).ok()?;
    Some(name.to_ascii_lowercase())
}

fn record(ver: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(REC_HEADER + payload.len());
    out.extend_from_slice(&[REC_HANDSHAKE, ver[0], ver[1]]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A cut point inside the hostname (or the middle of the message if there is no SNI).
fn mid_sni(hs: &[u8]) -> usize {
    let n = match sni_span(hs) {
        Some((off, len)) if len >= 2 => off + len / 2,
        _ => hs.len() / 2,
    };
    n.clamp(1, hs.len().saturating_sub(1).max(1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // they are all TLS-record splits
pub enum Strategy {
    /// Two TLS records split inside the hostname, one write.
    RecordSni,
    /// The same two records, each in its own TCP segment.
    RecordSniTcp,
    /// Three records across the hostname.
    RecordMulti,
    /// Two records, the first one byte long.
    RecordTiny,
}

pub const STRATEGIES: [Strategy; 4] = [
    Strategy::RecordSni,
    Strategy::RecordSniTcp,
    Strategy::RecordMulti,
    Strategy::RecordTiny,
];

impl Strategy {
    pub fn name(self) -> &'static str {
        match self {
            Strategy::RecordSni => "record-sni",
            Strategy::RecordSniTcp => "record-sni+tcp",
            Strategy::RecordMulti => "record-multi",
            Strategy::RecordTiny => "record-tiny",
        }
    }

    /// The writes (and pauses) that replace sending `rec` as-is.
    pub fn build(self, rec: &[u8]) -> Option<Vec<(Vec<u8>, Duration)>> {
        if rec.len() <= REC_HEADER + 1 || rec[0] != REC_HANDSHAKE {
            return None;
        }
        let ver = &rec[1..3];
        let hs = &rec[REC_HEADER..];
        let none = Duration::ZERO;
        Some(match self {
            Strategy::RecordSni => {
                let n = mid_sni(hs);
                let mut out = record(ver, &hs[..n]);
                out.extend(record(ver, &hs[n..]));
                vec![(out, none)]
            }
            Strategy::RecordSniTcp => {
                let n = mid_sni(hs);
                vec![
                    (record(ver, &hs[..n]), Duration::from_millis(12)),
                    (record(ver, &hs[n..]), none),
                ]
            }
            Strategy::RecordMulti => {
                let (mut a, mut b) = match sni_span(hs) {
                    Some((off, len)) if len >= 2 => (off.max(1), off + len / 2),
                    _ => (1, hs.len() / 2),
                };
                b = b.min(hs.len() - 1);
                if b <= a {
                    a = 1;
                    b = (hs.len() / 2).max(2).min(hs.len() - 1);
                }
                let mut out = record(ver, &hs[..a]);
                out.extend(record(ver, &hs[a..b]));
                out.extend(record(ver, &hs[b..]));
                vec![(out, none)]
            }
            Strategy::RecordTiny => {
                let mut out = record(ver, &hs[..1]);
                out.extend(record(ver, &hs[1..]));
                vec![(out, none)]
            }
        })
    }

    /// Send `rec` to `s` using this strategy.
    pub fn send(self, s: &mut TcpStream, rec: &[u8]) -> std::io::Result<()> {
        match self.build(rec) {
            Some(steps) => {
                for (data, pause) in steps {
                    s.write_all(&data)?;
                    if !pause.is_zero() {
                        sleep(pause);
                    }
                }
                Ok(())
            }
            None => s.write_all(rec),
        }
    }
}

#[cfg(test)]
pub fn sample_hello(host: &str) -> Vec<u8> {
    let h = host.as_bytes();
    let mut sni = vec![0u8];
    sni.extend((h.len() as u16).to_be_bytes());
    sni.extend(h);
    let mut list = (sni.len() as u16).to_be_bytes().to_vec();
    list.extend(&sni);
    let mut ext = vec![0, 0];
    ext.extend((list.len() as u16).to_be_bytes());
    ext.extend(&list);
    let mut body = vec![3, 3];
    body.extend([0u8; 32]);
    body.extend([0, 0, 2, 0x13, 1, 1, 0]);
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(&ext);
    let mut hs = vec![HS_CLIENT_HELLO, 0];
    hs.extend((body.len() as u16).to_be_bytes());
    hs.extend(&body);
    record(&[3, 1], &hs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reassemble the handshake bytes from a sequence of records.
    fn unrecord(mut b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while !b.is_empty() {
            assert_eq!(b[0], REC_HANDSHAKE);
            let n = usize::from(b[3]) << 8 | usize::from(b[4]);
            out.extend(&b[5..5 + n]);
            b = &b[5 + n..];
        }
        out
    }

    #[test]
    fn finds_sni() {
        let rec = sample_hello("www.Roblox.com");
        assert_eq!(sni(&rec).as_deref(), Some("www.roblox.com"));
        assert_eq!(sni(&rec[..20]), None);
    }

    #[test]
    fn every_strategy_keeps_the_handshake_and_splits_the_name() {
        let rec = sample_hello("discord.com");
        let hs = &rec[REC_HEADER..];
        for s in STRATEGIES {
            let wire: Vec<u8> = s
                .build(&rec)
                .unwrap()
                .into_iter()
                .flat_map(|(d, _)| d)
                .collect();
            assert_eq!(unrecord(&wire), hs, "{}", s.name());
            // the full name never appears in one piece
            let w = String::from_utf8_lossy(&wire);
            if s != Strategy::RecordTiny {
                assert!(!w.contains("discord.com"), "{}", s.name());
            }
        }
    }
}
