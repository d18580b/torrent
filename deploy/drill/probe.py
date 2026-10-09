"""Socket probes and a packet capture for the network-namespace drills.

Run by netns.sh and the drills as `python3 -I probe.py <command> ...`. Every
command prints one word (or one line) saying what happened, so a drill can
branch on it; none of them raises on a network error.

  bind-udp ADDR PORT [reuseaddr|reuseport|v6only ...]
      bound | <errno name>
  send-udp SRC SPORT DST DPORT [HOLD]
      sent <local port> | <errno name>   (SRC `-` and SPORT 0: unbound;
      the socket stays open HOLD seconds after the send)
  connect-tcp DST DPORT TIMEOUT [SRC]
      connected | refused | timeout | <errno name>
  probe-udp DST DPORT TIMEOUT
      reply | refused | timeout | <errno name>   (refused: an ICMP error came back)
  listen-tcp ADDR PORT
      accepts and closes connections until killed
  capture IFACE FILE
      writes `ready`, then one line per IP packet arriving on IFACE:
      `<proto> <src> <sport> <dst> <dport> [<tcp flags> | <icmp type>]`
  natpmp-gateway ADDR FILE [FIRST_PORT] [HOLD_ATTEMPTS]
      a NAT-PMP gateway on ADDR:5351 that moves every renewal to a new port
      and holds it on the wire; see natpmp_gateway
  fence-race DAEMON_LOG GATEWAY_LOG SKIP
      whether a fence landed inside a renewal, and what followed; see fence_race
"""

import errno
import socket
import struct
import sys
import time


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def err_name(e):
    return errno.errorcode.get(e.errno, str(e.errno)) if e.errno else type(e).__name__


def bind_udp(addr, port, *opts):
    s = socket.socket(family(addr), socket.SOCK_DGRAM)
    if "reuseaddr" in opts:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if "reuseport" in opts:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if family(addr) == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1 if "v6only" in opts else 0)
    try:
        s.bind((addr, int(port)))
        return "bound"
    except OSError as e:
        return err_name(e)
    finally:
        s.close()


def send_udp(src, sport, dst, dport, hold="0"):
    s = socket.socket(family(dst), socket.SOCK_DGRAM)
    try:
        if src != "-" or sport != "0":
            s.bind(("" if src == "-" else src, int(sport)))
        s.sendto(b"drill", (dst, int(dport)))
        # Kept open for `hold` seconds: a datagram a tunnel encrypts later,
        # off this call, matches `meta skuid` only while its socket is open.
        time.sleep(float(hold))
        return "sent %d" % s.getsockname()[1]
    except OSError as e:
        return err_name(e)
    finally:
        s.close()


def connect_tcp(dst, dport, timeout, src=None):
    s = socket.socket(family(dst), socket.SOCK_STREAM)
    s.settimeout(float(timeout))
    try:
        if src:
            s.bind((src, 0))
        s.connect((dst, int(dport)))
        return "connected"
    except ConnectionRefusedError:
        return "refused"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return err_name(e)
    finally:
        s.close()


def probe_udp(dst, dport, timeout):
    s = socket.socket(family(dst), socket.SOCK_DGRAM)
    s.settimeout(float(timeout))
    try:
        s.connect((dst, int(dport)))
        s.send(b"drill")
        s.recv(64)
        return "reply"
    except ConnectionRefusedError:
        return "refused"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return err_name(e)
    finally:
        s.close()


def listen_tcp(addr, port):
    s = socket.socket(family(addr), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(16)
    print("listening", flush=True)
    while True:
        c, _ = s.accept()
        c.close()


TCP_FLAGS = "FSRPAU"
# Neighbour discovery and MLD: the kernel's own housekeeping on any IPv6
# link, from no socket. Left out so a capture shows only what was sent.
ICMP6_HOUSEKEEPING = {133, 134, 135, 136, 137, 143}


def l4(proto, payload):
    if proto == 6 and len(payload) >= 14:
        sport, dport = struct.unpack("!HH", payload[:4])
        flags = "".join(f for i, f in enumerate(TCP_FLAGS) if payload[13] & (1 << i))
        return "tcp", sport, dport, flags
    if proto == 17 and len(payload) >= 4:
        sport, dport = struct.unpack("!HH", payload[:4])
        return "udp", sport, dport, ""
    if proto == 1 and payload:
        return "icmp", 0, 0, str(payload[0])
    if proto == 58 and payload:
        return "icmp6", 0, 0, str(payload[0])
    return "ip%d" % proto, 0, 0, ""


def capture(iface, path):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    with open(path, "a", buffering=1) as out:
        out.write("ready\n")
        while True:
            try:
                frame, addr = s.recvfrom(65535)
            except OSError:
                return  # the link went with the namespace
            if addr[2] == socket.PACKET_OUTGOING:
                continue
            ethertype = struct.unpack("!H", frame[12:14])[0]
            ip = frame[14:]
            if ethertype == 0x0800 and len(ip) >= 20:
                ihl = (ip[0] & 0x0F) * 4
                src, dst = socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20])
                proto, payload = ip[9], ip[ihl:]
            elif ethertype == 0x86DD and len(ip) >= 40:
                src, dst = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
                proto, payload = ip[6], ip[40:]
                # Hop-by-hop options (MLD reports carry one): skip to what follows.
                if proto == 0 and len(payload) >= 8:
                    proto, payload = payload[0], payload[(payload[1] + 1) * 8 :]
            else:
                continue
            name, sport, dport, extra = l4(proto, payload)
            if name == "icmp6" and int(extra) in ICMP6_HOUSEKEEPING:
                continue
            out.write(("%s %s %d %s %d %s" % (name, src, sport, dst, dport, extra)).rstrip() + "\n")


def natpmp_gateway(addr, log, first_port="40000", hold_attempts="5"):
    """A NAT-PMP gateway (RFC 6886) that changes the port on every renewal,
    and answers each renewal only at its client's `hold_attempts`th attempt.

    The first mapping exchange (the daemon's bring-up) is answered at once.
    After that every TCP mapping request is answered with a port it has not
    handed out before, so each renewal is a port change; and each request,
    TCP and UDP, is answered only when it has arrived `hold_attempts` times,
    which holds a renewal on the wire for most of the client's retransmit
    budget. The UDP answer repeats the TCP port. A delete (lifetime 0) is
    answered at once.

    `log` gets one line per renewal, in seconds since the epoch:
    `exchange <begin> <end> <port>`, from the first sight of its TCP request
    to the answer to its UDP one.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, 5351))
    epoch_base = time.time()
    port = int(first_port)
    hold = int(hold_attempts)
    exchanges = 0
    seen = {}
    begin = None
    with open(log, "a", buffering=1) as out:
        out.write("ready\n")
        while True:
            msg, peer = s.recvfrom(64)
            if len(msg) < 12 or msg[0] != 0 or msg[1] not in (1, 2):
                continue
            op = msg[1]
            internal = struct.unpack("!H", msg[4:6])[0]
            lifetime = struct.unpack("!I", msg[8:12])[0]
            if lifetime == 0:
                mapped = 0
            else:
                key = (op, msg)
                seen[key] = seen.get(key, 0) + 1
                if op == 2 and seen[key] == 1 and exchanges > 0:
                    begin = time.time()
                if exchanges > 0 and seen[key] < hold:
                    continue
                del seen[key]
                if op == 2:
                    if exchanges > 0:
                        port += 1
                    tcp_port = port
                mapped = port
            epoch = int(time.time() - epoch_base) + 1
            s.sendto(
                struct.pack("!BBHIHHI", 0, 128 + op, 0, epoch, internal, mapped, lifetime and 4),
                peer,
            )
            if op == 1 and lifetime:
                if exchanges > 0 and begin is not None:
                    out.write("exchange %.3f %.3f %d\n" % (begin, time.time(), tcp_port))
                exchanges += 1


FENCE = "VPN tunnel unhealthy"
REBOUND = "NAT-PMP port changed; rebound live session"
HELD = "NAT-PMP renewed with a new port after the profile was fenced"
REANNOUNCED = "reannounced the profile's torrents after the port change"


def fence_race(daemon_log, gateway_log, skip):
    """Judge one fence from the daemon's JSON log (from line `skip` on) and
    the gateway's exchanges: whether it landed inside a renewal's exchange,
    and what the renewal did after it.

    Prints `<hit|miss> <rebound|held|none> fence=<t> [exchange=<begin>-<end>]`,
    or `nofence`.
    """
    from datetime import datetime
    import json

    events = []
    with open(daemon_log) as f:
        for i, line in enumerate(f):
            if i < int(skip):
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            t = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
            events.append((t, e.get("message", "")))
    fenced = [t for t, m in events if m.startswith(FENCE)]
    if not fenced:
        return "nofence"
    t_f = fenced[0]
    exchanges = []
    with open(gateway_log) as f:
        for line in f:
            parts = line.split()
            if parts and parts[0] == "exchange":
                exchanges.append((float(parts[1]), float(parts[2])))
    hit = [(b, e) for b, e in exchanges if b < t_f < e]
    after = [m for t, m in events if t > t_f]
    if any(m.startswith(REBOUND) or m.startswith(REANNOUNCED) for m in after):
        did = "rebound"
    elif any(m.startswith(HELD) for m in after):
        did = "held"
    else:
        did = "none"
    verdict = "%s %s fence=%.3f" % ("hit" if hit else "miss", did, t_f)
    if hit:
        verdict += " exchange=%.3f-%.3f" % hit[0]
    return verdict


COMMANDS = {
    "bind-udp": bind_udp,
    "send-udp": send_udp,
    "connect-tcp": connect_tcp,
    "probe-udp": probe_udp,
    "listen-tcp": listen_tcp,
    "capture": capture,
    "natpmp-gateway": natpmp_gateway,
    "fence-race": fence_race,
}

if __name__ == "__main__":
    result = COMMANDS[sys.argv[1]](*sys.argv[2:])
    if result is not None:
        print(result, flush=True)
