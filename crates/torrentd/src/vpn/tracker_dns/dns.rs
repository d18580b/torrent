//! The two DNS messages the tunnel resolver needs (RFC 1035): one question
//! for a name's A or AAAA records, and the addresses in the answer to it.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub(super) const TYPE_A: u16 = 1;
pub(super) const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u8 = 3;

/// The addresses an answer holds, and the shortest TTL among them.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Answer {
    pub(super) addrs: Vec<IpAddr>,
    pub(super) ttl: u32,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum Error {
    /// Not an answer to the question asked: another id, not a response, or
    /// another question. Ignored, as a stray datagram is.
    #[error("not an answer to this question")]
    NotOurs,
    #[error("the resolver answered with rcode {0}")]
    Rcode(u8),
    #[error("the answer was truncated")]
    Truncated,
    #[error("the answer is malformed")]
    Malformed,
    #[error("{0:?} is not a hostname")]
    BadName(String),
}

/// A recursive query for `name`'s records of `qtype`.
pub(super) fn query(id: u16, name: &str, qtype: u16) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    // RD set; one question.
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&mut out, name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), Error> {
    let bad = || Error::BadName(name.to_string());
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(bad());
    }
    for label in trimmed.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(bad());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// The addresses of type `qtype` in `msg`, the answer to [`query`]`(id,
/// name, qtype)`. A name that does not exist is an answer with no address.
pub(super) fn answer(msg: &[u8], id: u16, name: &str, qtype: u16) -> Result<Answer, Error> {
    if msg.len() < 12 || msg[..2] != id.to_be_bytes() || msg[2] & 0x80 == 0 {
        return Err(Error::NotOurs);
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    if qdcount != 1 {
        return Err(Error::NotOurs);
    }
    let mut asked = Vec::new();
    encode_name(&mut asked, name)?;
    let mut at = 12;
    let (qname, next) = read_name(msg, at)?;
    at = next;
    let qtail = msg.get(at..at + 4).ok_or(Error::Malformed)?;
    if !qname.eq_ignore_ascii_case(&asked) || qtail[..2] != qtype.to_be_bytes() {
        return Err(Error::NotOurs);
    }
    at += 4;
    if msg[2] & 0x02 != 0 {
        return Err(Error::Truncated);
    }
    match msg[3] & 0x0f {
        0 => {}
        RCODE_NXDOMAIN => {
            return Ok(Answer {
                addrs: vec![],
                ttl: 0,
            })
        }
        rcode => return Err(Error::Rcode(rcode)),
    }
    let mut addrs = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..ancount {
        let (_, next) = read_name(msg, at)?;
        at = next;
        let rr = msg.get(at..at + 10).ok_or(Error::Malformed)?;
        let rtype = u16::from_be_bytes([rr[0], rr[1]]);
        let rclass = u16::from_be_bytes([rr[2], rr[3]]);
        let rttl = u32::from_be_bytes([rr[4], rr[5], rr[6], rr[7]]);
        let rdlen = usize::from(u16::from_be_bytes([rr[8], rr[9]]));
        at += 10;
        let rdata = msg.get(at..at + rdlen).ok_or(Error::Malformed)?;
        at += rdlen;
        // CNAMEs are followed by the resolver, which puts the target's
        // records in the same answer; only the addresses are read.
        if rclass != CLASS_IN || rtype != qtype {
            continue;
        }
        let addr = match (rtype, rdata.len()) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (TYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return Err(Error::Malformed),
        };
        addrs.push(addr);
        ttl = ttl.min(rttl);
    }
    if addrs.is_empty() {
        ttl = 0;
    }
    Ok(Answer { addrs, ttl })
}

/// The name at `at`, in its wire form with every pointer followed, and the
/// offset just past it where it sits.
fn read_name(msg: &[u8], mut at: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut name = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(at).ok_or(Error::Malformed)?;
        match len {
            0 => {
                name.push(0);
                return Ok((name, end.unwrap_or(at + 1)));
            }
            l if l & 0xc0 == 0xc0 => {
                let lo = *msg.get(at + 1).ok_or(Error::Malformed)?;
                end.get_or_insert(at + 2);
                jumps += 1;
                if jumps > 16 {
                    return Err(Error::Malformed);
                }
                at = usize::from(u16::from_be_bytes([l & 0x3f, lo]));
            }
            l if l & 0xc0 == 0 => {
                let label = msg
                    .get(at + 1..at + 1 + usize::from(l))
                    .ok_or(Error::Malformed)?;
                name.push(l);
                name.extend_from_slice(label);
                if name.len() > 255 {
                    return Err(Error::Malformed);
                }
                at += 1 + usize::from(l);
            }
            _ => return Err(Error::Malformed),
        }
    }
}
