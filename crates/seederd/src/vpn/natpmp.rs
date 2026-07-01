//! Native NAT-PMP client (RFC 6886) for VPN gateways that hand out an
//! ephemeral forwarded port (ProtonVPN, PIA, …).
//!
//! Unlike the VPN bring-up paths, this does **not** shell out — NAT-PMP is a
//! tiny fixed-layout UDP protocol, so an in-process client avoids a runtime
//! dependency on `libnatpmp`'s `natpmpc` binary.
//!
//! # No-leak guarantee
//! The request socket is bound to the **tunnel IP** (`PortMapRequest::bind_ip`)
//! and `connect()`ed to the gateway, so the negotiation egresses *inside* the
//! tunnel and can never leak over the bare interface.
//!
//! # Wire format (RFC 6886 §3.2)
//! Request (12 bytes): `ver=0, opcode, reserved=0u16, internal_port,
//! suggested_external_port, lifetime_secs`.
//! Response (16 bytes): `ver=0, opcode|0x80, result_code, epoch,
//! internal_port, mapped_external_port, lifetime_secs`.
//!
//! For BitTorrent we request both a UDP (uTP/DHT) and a TCP (peer) mapping and
//! bind libtorrent to the returned public port.

use std::io;
use std::net::UdpSocket;
use std::time::Duration;

use seederd_engine::PortForwardError;
use seederd_engine::PortForwarder;
use seederd_engine::PortMapRequest;
use tracing::warn;

/// Well-known NAT-PMP server port on the gateway.
const NATPMP_PORT: u16 = 5351;
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;
/// Responses set the high bit of the request opcode.
const RESP_OPCODE_FLAG: u8 = 0x80;

/// Native RFC 6886 NAT-PMP client. Stateless; each `map` call opens a fresh
/// socket, so it is safe to renew from a background task on every tick.
#[derive(Debug, Clone)]
pub struct NatpmpForwarder {
    gateway_port: u16,
    /// Retransmission schedule: one read timeout per attempt. RFC 6886 doubles
    /// the timeout each retry; we bound it so startup stays responsive.
    timeouts: Vec<Duration>,
}

impl Default for NatpmpForwarder {
    fn default() -> Self {
        Self {
            gateway_port: NATPMP_PORT,
            timeouts: vec![
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_millis(1000),
                Duration::from_millis(2000),
            ],
        }
    }
}

impl NatpmpForwarder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue one mapping request (single protocol) with retransmission, and
    /// return the gateway-assigned public port.
    fn map_one(
        &self,
        sock: &UdpSocket,
        opcode: u8,
        req: &PortMapRequest,
    ) -> Result<u16, PortForwardError> {
        // Suggested external port 0 = "no preference"; the gateway assigns one
        // (the ProtonVPN convention).
        let msg = encode_request(opcode, req.internal_port, 0, req.lifetime_secs);
        for t in &self.timeouts {
            sock.set_read_timeout(Some(*t))
                .map_err(|e| PortForwardError::Io(e.to_string()))?;
            sock.send(&msg)
                .map_err(|e| PortForwardError::Io(e.to_string()))?;
            let mut buf = [0u8; 16];
            match sock.recv(&mut buf) {
                Ok(n) => return decode_response(&buf[..n], opcode),
                Err(e) if is_timeout(&e) => continue,
                Err(e) => return Err(PortForwardError::Io(e.to_string())),
            }
        }
        Err(PortForwardError::Timeout {
            gateway: req.gateway,
        })
    }
}

impl PortForwarder for NatpmpForwarder {
    fn map(&self, req: &PortMapRequest) -> Result<u16, PortForwardError> {
        // Bind to the tunnel IP so the request never leaves the tunnel.
        let sock = UdpSocket::bind((req.bind_ip, 0))
            .map_err(|e| PortForwardError::Io(format!("bind {}: {e}", req.bind_ip)))?;
        sock.connect((req.gateway, self.gateway_port))
            .map_err(|e| PortForwardError::Io(format!("connect {}: {e}", req.gateway)))?;

        let udp_port = self.map_one(&sock, OP_MAP_UDP, req)?;
        let tcp_port = self.map_one(&sock, OP_MAP_TCP, req)?;
        if udp_port != tcp_port {
            warn!(
                target: "seederd::vpn::natpmp",
                udp_port,
                tcp_port,
                "NAT-PMP gateway returned different UDP/TCP ports; binding the TCP port",
            );
        }
        // BitTorrent inbound peer connections are primarily TCP.
        Ok(tcp_port)
    }
}

/// Encode a 12-byte NAT-PMP mapping request.
fn encode_request(opcode: u8, internal: u16, suggested_external: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0; // version
    b[1] = opcode;
    // b[2..4] reserved = 0
    b[4..6].copy_from_slice(&internal.to_be_bytes());
    b[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// Decode a NAT-PMP mapping response, returning the mapped public port on
/// success. `req_opcode` is the opcode we sent (the response echoes it with the
/// high bit set).
fn decode_response(buf: &[u8], req_opcode: u8) -> Result<u16, PortForwardError> {
    if buf.len() < 16 {
        return Err(PortForwardError::Parse(format!(
            "response too short: {} bytes",
            buf.len()
        )));
    }
    if buf[0] != 0 {
        return Err(PortForwardError::Parse(format!(
            "unexpected version {}",
            buf[0]
        )));
    }
    if buf[1] != req_opcode | RESP_OPCODE_FLAG {
        return Err(PortForwardError::Parse(format!(
            "unexpected opcode {} (wanted {})",
            buf[1],
            req_opcode | RESP_OPCODE_FLAG
        )));
    }
    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return Err(PortForwardError::Gateway(result_code));
    }
    let external = u16::from_be_bytes([buf[10], buf[11]]);
    if external == 0 {
        return Err(PortForwardError::Parse(
            "gateway mapped external port 0".to_string(),
        ));
    }
    Ok(external)
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::thread;

    use super::*;

    #[test]
    fn request_encoding_matches_rfc_layout() {
        let b = encode_request(OP_MAP_UDP, 0, 0, 60);
        assert_eq!(b[0], 0); // version
        assert_eq!(b[1], 1); // opcode UDP
        assert_eq!(&b[2..4], &[0, 0]); // reserved
        assert_eq!(&b[4..6], &0u16.to_be_bytes()); // internal
        assert_eq!(&b[6..8], &0u16.to_be_bytes()); // suggested external
        assert_eq!(&b[8..12], &60u32.to_be_bytes()); // lifetime
    }

    fn success_response(req_opcode: u8, external: u16) -> [u8; 16] {
        let mut r = [0u8; 16];
        r[0] = 0;
        r[1] = req_opcode | RESP_OPCODE_FLAG;
        // result_code = 0, epoch = 0, internal = 0
        r[10..12].copy_from_slice(&external.to_be_bytes());
        r[12..16].copy_from_slice(&60u32.to_be_bytes());
        r
    }

    #[test]
    fn decode_success_returns_mapped_port() {
        let r = success_response(OP_MAP_TCP, 40001);
        assert_eq!(decode_response(&r, OP_MAP_TCP).unwrap(), 40001);
    }

    #[test]
    fn decode_rejects_short_wrong_version_opcode_and_zero_port() {
        assert!(matches!(
            decode_response(&[0u8; 8], OP_MAP_TCP),
            Err(PortForwardError::Parse(_))
        ));
        let mut bad_ver = success_response(OP_MAP_TCP, 40001);
        bad_ver[0] = 9;
        assert!(matches!(
            decode_response(&bad_ver, OP_MAP_TCP),
            Err(PortForwardError::Parse(_))
        ));
        // Response echoes UDP opcode but we asked for TCP.
        let mismatched = success_response(OP_MAP_UDP, 40001);
        assert!(matches!(
            decode_response(&mismatched, OP_MAP_TCP),
            Err(PortForwardError::Parse(_))
        ));
        let zero = success_response(OP_MAP_TCP, 0);
        assert!(matches!(
            decode_response(&zero, OP_MAP_TCP),
            Err(PortForwardError::Parse(_))
        ));
    }

    #[test]
    fn decode_surfaces_gateway_result_code() {
        let mut r = success_response(OP_MAP_TCP, 40001);
        r[2..4].copy_from_slice(&3u16.to_be_bytes()); // e.g. "network failure"
        assert!(matches!(
            decode_response(&r, OP_MAP_TCP),
            Err(PortForwardError::Gateway(3))
        ));
    }

    /// Fast test-only forwarder pointed at a loopback fake gateway.
    fn test_forwarder(gateway_port: u16) -> NatpmpForwarder {
        NatpmpForwarder {
            gateway_port,
            timeouts: vec![Duration::from_millis(500), Duration::from_millis(500)],
        }
    }

    #[test]
    fn loopback_negotiates_port_over_udp_socket() {
        // Fake NAT-PMP gateway on localhost: answers UDP then TCP with 40001.
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let mut buf = [0u8; 12];
                let (_n, peer) = gw.recv_from(&mut buf).unwrap();
                let resp = success_response(buf[1], 40001);
                gw.send_to(&resp, peer).unwrap();
            }
        });

        let fwd = test_forwarder(gw_port);
        let req = PortMapRequest {
            gateway: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            internal_port: 0,
            lifetime_secs: 60,
        };
        assert_eq!(fwd.map(&req).unwrap(), 40001);
        server.join().unwrap();
    }

    #[test]
    fn loopback_surfaces_gateway_error() {
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 12];
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            let mut resp = success_response(buf[1], 40001);
            resp[2..4].copy_from_slice(&2u16.to_be_bytes()); // "not authorized"
            gw.send_to(&resp, peer).unwrap();
        });

        let fwd = test_forwarder(gw_port);
        let req = PortMapRequest {
            gateway: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            internal_port: 0,
            lifetime_secs: 60,
        };
        assert!(matches!(fwd.map(&req), Err(PortForwardError::Gateway(2))));
        server.join().unwrap();
    }
}
