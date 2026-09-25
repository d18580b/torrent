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
use std::net::IpAddr;
use std::net::UdpSocket;
use std::time::Duration;

use torrentd_engine::MapResult;
use torrentd_engine::PortForwardError;
use torrentd_engine::PortForwarder;
use torrentd_engine::PortMapRequest;
use tracing::warn;

/// Well-known NAT-PMP server port on the gateway.
const NATPMP_PORT: u16 = 5351;
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;
/// Responses set the high bit of the request opcode.
const RESP_OPCODE_FLAG: u8 = 0x80;

/// Retransmission schedules (ms), one read timeout per attempt. RFC 6886 §3.1
/// doubles the timeout each retry; the full 9-retry/~128s schedule would exceed
/// our 45s renewal interval and 60s lease, so both profiles are bounded well
/// under that. A lost *renewal* is soft (retried next tick), so it stays snappy;
/// a lost *startup* negotiate disables the profile, so it gets the longer budget to
/// ride out a lossy boot.
const RENEWAL_TIMEOUTS_MS: &[u64] = &[250, 500, 1000, 2000, 4000]; // ~7.75s
const STARTUP_TIMEOUTS_MS: &[u64] = &[250, 500, 1000, 2000, 4000, 8000]; // ~15.75s
/// Teardown is best-effort on the shutdown path; keep it quick.
const TEARDOWN_TIMEOUTS_MS: &[u64] = &[250, 500];

/// Native RFC 6886 NAT-PMP client. Stateless; each `map` call opens a fresh
/// socket, so it is safe to renew from a background task on every tick.
#[derive(Debug, Clone)]
pub struct NatpmpForwarder {
    gateway_port: u16,
    /// Retransmission schedule: one read timeout per attempt.
    timeouts: Vec<Duration>,
    /// Whether `map` releases a UDP mapping the gateway put on a different
    /// port from the TCP one.
    ///
    /// That release is `delete_one`, i.e. RFC 6886 §3.4's *wildcard* delete:
    /// internal port 0, lifetime 0, which removes **every** mapping the
    /// requesting address holds for the protocol. On the daemon's own paths
    /// that is what is wanted — the orphan is the daemon's and a UDP mapping
    /// on a port libtorrent cannot bind is useless to it. For a client that is
    /// only *asking what the gateway would do*, it is not: the socket is bound
    /// to the tunnel address, which is the daemon's NAT-PMP identity, so the
    /// wildcard delete destroys the running daemon's live UDP forward.
    ///
    /// A wrapper around `map` cannot prevent this, because the delete is
    /// inside `map`. It has to be a property of the client.
    release_divergent_udp: bool,
}

impl Default for NatpmpForwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl NatpmpForwarder {
    /// Client for steady-state renewals (snappy retransmit budget).
    pub fn new() -> Self {
        Self::with_timeouts_ms(RENEWAL_TIMEOUTS_MS, true)
    }

    /// Client for the one-shot startup negotiate (longer budget: failure here
    /// disables the profile).
    pub fn for_startup() -> Self {
        Self::with_timeouts_ms(STARTUP_TIMEOUTS_MS, true)
    }

    /// Client for a read-only pre-flight — `torrentd vpn check` — which must
    /// not delete anything on any branch.
    ///
    /// Same retransmit budget as [`Self::for_startup`], because it is asking
    /// the same one-shot question, but it leaves a divergent UDP mapping to
    /// expire with its lease instead of issuing the wildcard delete. A
    /// diagnostic that can take a running daemon's forward down is not a
    /// diagnostic.
    pub fn for_probe() -> Self {
        Self::with_timeouts_ms(STARTUP_TIMEOUTS_MS, false)
    }

    /// Whether this client will issue NAT-PMP's wildcard delete for a
    /// divergent UDP mapping. False for [`Self::for_probe`] and true for the
    /// two clients the daemon itself uses.
    ///
    /// Test-only: which client a call site picked is a property worth holding
    /// in place, and it is not one any caller should branch on at runtime.
    #[cfg(test)]
    pub fn deletes_divergent_udp(&self) -> bool {
        self.release_divergent_udp
    }

    fn with_timeouts_ms(ms: &[u64], release_divergent_udp: bool) -> Self {
        Self {
            gateway_port: NATPMP_PORT,
            timeouts: ms.iter().map(|&m| Duration::from_millis(m)).collect(),
            release_divergent_udp,
        }
    }

    /// Issue one mapping request (single protocol) with retransmission, and
    /// return the gateway-assigned public port and epoch. `suggested_external`
    /// is the port we'd prefer (0 = no preference); the gateway is free to
    /// assign a different one.
    fn map_one(
        &self,
        sock: &UdpSocket,
        opcode: u8,
        req: &PortMapRequest,
        suggested_external: u16,
    ) -> Result<(u16, u32), PortForwardError> {
        let msg = encode_request(
            opcode,
            req.internal_port,
            suggested_external,
            req.lifetime_secs,
        );
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

    /// Release this client's mappings (RFC 6886 §3.4: internal port 0 + lifetime
    /// 0 deletes all of the client's mappings for the protocol). Best-effort,
    /// bound to the tunnel IP like `map`, and used on graceful shutdown so a
    /// stale mapping doesn't linger for the ~60s lease. Uses a short retransmit
    /// budget so it can't stall shutdown.
    pub fn unmap(&self, gateway: IpAddr, bind_ip: IpAddr) -> Result<(), PortForwardError> {
        let sock = UdpSocket::bind((bind_ip, 0))
            .map_err(|e| PortForwardError::Io(format!("bind {bind_ip}: {e}")))?;
        sock.connect((gateway, self.gateway_port))
            .map_err(|e| PortForwardError::Io(format!("connect {gateway}: {e}")))?;
        self.delete_one(&sock, OP_MAP_UDP, gateway)?;
        self.delete_one(&sock, OP_MAP_TCP, gateway)?;
        Ok(())
    }

    fn delete_one(
        &self,
        sock: &UdpSocket,
        opcode: u8,
        gateway: IpAddr,
    ) -> Result<(), PortForwardError> {
        // internal port 0, suggested external 0, lifetime 0 = delete.
        let msg = encode_request(opcode, 0, 0, 0);
        for &m in TEARDOWN_TIMEOUTS_MS {
            sock.set_read_timeout(Some(Duration::from_millis(m)))
                .map_err(|e| PortForwardError::Io(e.to_string()))?;
            sock.send(&msg)
                .map_err(|e| PortForwardError::Io(e.to_string()))?;
            let mut buf = [0u8; 16];
            match sock.recv(&mut buf) {
                Ok(n) => return decode_delete(&buf[..n], opcode),
                Err(e) if is_timeout(&e) => continue,
                Err(e) => return Err(PortForwardError::Io(e.to_string())),
            }
        }
        Err(PortForwardError::Timeout { gateway })
    }
}

impl PortForwarder for NatpmpForwarder {
    fn map(&self, req: &PortMapRequest) -> Result<MapResult, PortForwardError> {
        // Bind to the tunnel IP so the request never leaves the tunnel.
        let sock = UdpSocket::bind((req.bind_ip, 0))
            .map_err(|e| PortForwardError::Io(format!("bind {}: {e}", req.bind_ip)))?;
        sock.connect((req.gateway, self.gateway_port))
            .map_err(|e| PortForwardError::Io(format!("connect {}: {e}", req.gateway)))?;

        // TCP carries inbound BitTorrent peers, so map it first and let it be
        // authoritative, suggesting the port the caller already holds (0 on
        // the first negotiation) so a renewal asks to keep it. Then ask for a
        // UDP (uTP) mapping on the *same* external port so libtorrent — which
        // binds TCP + uTP to one listen port — gets a consistent forward.
        let (tcp_port, epoch) = self.map_one(&sock, OP_MAP_TCP, req, req.suggested_port)?;
        let udp_mapped = match self.map_one(&sock, OP_MAP_UDP, req, tcp_port) {
            Ok((udp_port, _)) if udp_port == tcp_port => true,
            Ok((udp_port, _)) => {
                // Gateway wouldn't honour the suggestion. A UDP mapping on a
                // different port is useless (we can't split the listen port), so
                // release it rather than leave it orphaned until the lease ends.
                //
                // Except for a probe client: the release is the wildcard
                // delete, and it is issued from the tunnel address, which is
                // the *daemon's* NAT-PMP identity. Tidying an orphan is worth
                // a wildcard delete on the paths that own the mapping; it is
                // never worth one on a path whose contract is that it changes
                // nothing.
                if self.release_divergent_udp {
                    warn!(
                        target: "torrentd::vpn::natpmp",
                        udp_port,
                        tcp_port,
                        "NAT-PMP gateway assigned divergent UDP/TCP ports; releasing the UDP mapping and binding TCP",
                    );
                    let _ = self.delete_one(&sock, OP_MAP_UDP, req.gateway);
                } else {
                    warn!(
                        target: "torrentd::vpn::natpmp",
                        udp_port,
                        tcp_port,
                        "NAT-PMP gateway assigned divergent UDP/TCP ports; leaving the UDP mapping to expire (this client deletes nothing)",
                    );
                }
                false
            }
            Err(e) => {
                // UDP is best-effort for a seeder; TCP already succeeded. The
                // caller reports `udp_mapped = false` as a metric, since uTP
                // peers cannot reach the session until a renewal maps it.
                warn!(
                    target: "torrentd::vpn::natpmp",
                    tcp_port,
                    error.cause = %e,
                    "NAT-PMP UDP mapping failed; proceeding with TCP only",
                );
                false
            }
        };
        Ok(MapResult {
            port: tcp_port,
            epoch,
            udp_mapped,
        })
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

/// Decode a NAT-PMP mapping response, returning the mapped public port and the
/// gateway epoch (`buf[4..8]`, seconds since the gateway booted) on success.
/// `req_opcode` is the opcode we sent (the response echoes it with the high bit
/// set).
fn decode_response(buf: &[u8], req_opcode: u8) -> Result<(u16, u32), PortForwardError> {
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
    let epoch = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let external = u16::from_be_bytes([buf[10], buf[11]]);
    if external == 0 {
        return Err(PortForwardError::Parse(
            "gateway mapped external port 0".to_string(),
        ));
    }
    Ok((external, epoch))
}

/// Decode a NAT-PMP deletion (lifetime-0) response. Unlike a mapping response,
/// the mapped external port is legitimately 0, so we only validate the header
/// and result code.
fn decode_delete(buf: &[u8], req_opcode: u8) -> Result<(), PortForwardError> {
    if buf.len() < 16 {
        return Err(PortForwardError::Parse(format!(
            "delete response too short: {} bytes",
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
    Ok(())
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
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
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
        assert_eq!(decode_response(&r, OP_MAP_TCP).unwrap(), (40001, 0));
    }

    #[test]
    fn decode_parses_gateway_epoch() {
        let mut r = success_response(OP_MAP_TCP, 40001);
        r[4..8].copy_from_slice(&123_456u32.to_be_bytes());
        assert_eq!(decode_response(&r, OP_MAP_TCP).unwrap(), (40001, 123_456));
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
            release_divergent_udp: true,
        }
    }

    /// The same fast client with the probe client's delete policy.
    fn test_probe_forwarder(gateway_port: u16) -> NatpmpForwarder {
        NatpmpForwarder {
            release_divergent_udp: false,
            ..test_forwarder(gateway_port)
        }
    }

    /// A request against a loopback fake gateway, the way the daemon builds
    /// one: the fixed internal port and the caller's suggested external port.
    fn loopback_req(suggested_port: u16) -> PortMapRequest {
        PortMapRequest {
            gateway: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            internal_port: PortMapRequest::INTERNAL_PORT,
            suggested_port,
            lifetime_secs: 60,
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
        let req = loopback_req(0);
        let m = fwd.map(&req).unwrap();
        assert_eq!(m.port, 40001);
        assert!(m.udp_mapped, "UDP landed on the TCP port");
        server.join().unwrap();
    }

    #[test]
    fn a_renewal_names_internal_port_1_and_asks_to_keep_the_held_port() {
        // What goes on the wire: RFC 6886 reserves internal port 0 for the
        // delete-all request, and Proton documents `natpmpc -a 1 0 …`. The
        // TCP request suggests the port the session already listens on; the
        // UDP request then suggests whatever TCP was given.
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let mut buf = [0u8; 12];
                let (_n, peer) = gw.recv_from(&mut buf).unwrap();
                seen.push(buf);
                gw.send_to(&success_response(buf[1], 51413), peer).unwrap();
            }
            seen
        });

        let fwd = test_forwarder(gw_port);
        assert_eq!(fwd.map(&loopback_req(51413)).unwrap().port, 51413);
        let seen = server.join().unwrap();
        assert_eq!(seen[0][1], OP_MAP_TCP);
        assert_eq!(&seen[0][4..6], &1u16.to_be_bytes(), "internal port 1");
        assert_eq!(
            &seen[0][6..8],
            &51413u16.to_be_bytes(),
            "held port suggested"
        );
        assert_eq!(seen[1][1], OP_MAP_UDP);
        assert_eq!(&seen[1][4..6], &1u16.to_be_bytes(), "internal port 1");
        assert_eq!(
            &seen[1][6..8],
            &51413u16.to_be_bytes(),
            "TCP's port suggested"
        );
    }

    #[test]
    fn a_failed_udp_mapping_is_reported_not_swallowed() {
        // TCP maps; the gateway refuses UDP. The TCP port is still the
        // answer, and the result says uTP peers cannot reach it.
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 12];
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(buf[1], OP_MAP_TCP);
            gw.send_to(&success_response(buf[1], 40001), peer).unwrap();
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(buf[1], OP_MAP_UDP);
            let mut refused = success_response(buf[1], 40001);
            refused[2..4].copy_from_slice(&4u16.to_be_bytes()); // out of resources
            gw.send_to(&refused, peer).unwrap();
        });

        let fwd = test_forwarder(gw_port);
        let m = fwd.map(&loopback_req(0)).unwrap();
        server.join().unwrap();
        assert_eq!(m.port, 40001);
        assert!(!m.udp_mapped);
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
        let req = loopback_req(0);
        assert!(matches!(fwd.map(&req), Err(PortForwardError::Gateway(2))));
        server.join().unwrap();
    }

    #[test]
    fn loopback_divergent_udp_is_released_and_tcp_bound() {
        // Gateway maps TCP=40001 but ignores the suggestion and hands UDP=40002.
        // map() must return the TCP port and release the orphan UDP mapping.
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let saw_udp_delete = Arc::new(AtomicBool::new(false));
        let flag = saw_udp_delete.clone();
        let server = thread::spawn(move || {
            // 1) TCP map → 40001
            let mut buf = [0u8; 12];
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(buf[1], OP_MAP_TCP);
            gw.send_to(&success_response(buf[1], 40001), peer).unwrap();
            // 2) UDP map, suggested 40001 → gateway insists on 40002
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(buf[1], OP_MAP_UDP);
            assert_eq!(&buf[6..8], &40001u16.to_be_bytes()); // we suggested TCP's port
            gw.send_to(&success_response(buf[1], 40002), peer).unwrap();
            // 3) UDP deletion (lifetime 0)
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            if buf[1] == OP_MAP_UDP && buf[8..12] == 0u32.to_be_bytes() {
                flag.store(true, Ordering::SeqCst);
            }
            gw.send_to(&success_response(buf[1], 0), peer).unwrap();
        });

        let fwd = test_forwarder(gw_port);
        let req = loopback_req(0);
        assert_eq!(fwd.map(&req).unwrap().port, 40001);
        server.join().unwrap();
        assert!(
            saw_udp_delete.load(Ordering::SeqCst),
            "divergent UDP mapping should have been released",
        );
    }

    #[test]
    fn a_probe_client_issues_no_delete_on_the_divergent_udp_branch() {
        // The check's contract is that the flagless path deletes nothing. The
        // call site cannot hold that: the delete lives *inside* `map`, on the
        // branch where the gateway ignores the suggested UDP port, and the
        // socket it is sent from is bound to the tunnel address — the running
        // daemon's own NAT-PMP identity. `delete_one` is the RFC 6886 §3.4
        // wildcard form, so what it removes is every mapping that address
        // holds, i.e. the daemon's live UDP (uTP/DHT) forward.
        //
        // Same gateway script as `loopback_divergent_udp_is_released_and_tcp_bound`,
        // which asserts the opposite for the daemon's own clients: TCP 40001,
        // UDP insists on 40002. The gateway then waits for a third datagram
        // that must not come.
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        gw.set_read_timeout(Some(Duration::from_millis(750)))
            .unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let saw_a_third_request = Arc::new(AtomicBool::new(false));
        let flag = saw_a_third_request.clone();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 12];
            // 1) TCP map → 40001
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(buf[1], OP_MAP_TCP);
            gw.send_to(&success_response(buf[1], 40001), peer).unwrap();
            // 2) UDP map, suggested 40001 → gateway insists on 40002
            let (_n, peer) = gw.recv_from(&mut buf).unwrap();
            assert_eq!(buf[1], OP_MAP_UDP);
            gw.send_to(&success_response(buf[1], 40002), peer).unwrap();
            // 3) Nothing. A datagram here is the wildcard delete.
            if gw.recv_from(&mut buf).is_ok() {
                flag.store(true, Ordering::SeqCst);
            }
        });

        let fwd = test_probe_forwarder(gw_port);
        let req = loopback_req(0);
        // The TCP port is still what the caller gets: refusing to delete does
        // not cost the answer the check exists to obtain.
        assert_eq!(fwd.map(&req).unwrap().port, 40001);
        server.join().unwrap();
        assert!(
            !saw_a_third_request.load(Ordering::SeqCst),
            "a probe client sent a request after the two mappings; the only thing it could \
             be is the wildcard delete this client exists to not send",
        );
    }

    #[test]
    fn only_the_daemon_s_own_clients_delete_anything() {
        // Which client the check picks is the whole repair, so the property is
        // asserted on the constructors rather than inferred from a call site.
        assert!(NatpmpForwarder::new().deletes_divergent_udp());
        assert!(NatpmpForwarder::for_startup().deletes_divergent_udp());
        assert!(!NatpmpForwarder::for_probe().deletes_divergent_udp());
    }

    #[test]
    fn the_probe_client_keeps_the_startup_retransmit_budget() {
        assert_eq!(
            NatpmpForwarder::for_probe().timeouts,
            NatpmpForwarder::for_startup().timeouts,
        );
    }

    #[test]
    fn startup_profile_has_more_retransmits_than_renewal() {
        assert!(
            NatpmpForwarder::for_startup().timeouts.len() > NatpmpForwarder::new().timeouts.len()
        );
    }

    #[test]
    fn loopback_unmap_releases_mapping() {
        // Fake gateway answers the UDP then TCP deletion requests.
        let gw = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gw_port = gw.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let mut buf = [0u8; 12];
                let (_n, peer) = gw.recv_from(&mut buf).unwrap();
                // A deletion request carries lifetime 0 (RFC 6886 §3.4).
                assert_eq!(&buf[8..12], &0u32.to_be_bytes());
                let resp = success_response(buf[1], 0); // external port 0 = deleted
                gw.send_to(&resp, peer).unwrap();
            }
        });

        let fwd = test_forwarder(gw_port);
        fwd.unmap(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .unwrap();
        server.join().unwrap();
    }
}
