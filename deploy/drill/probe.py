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
            frame, addr = s.recvfrom(65535)
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


COMMANDS = {
    "bind-udp": bind_udp,
    "send-udp": send_udp,
    "connect-tcp": connect_tcp,
    "probe-udp": probe_udp,
    "listen-tcp": listen_tcp,
    "capture": capture,
}

if __name__ == "__main__":
    result = COMMANDS[sys.argv[1]](*sys.argv[2:])
    if result is not None:
        print(result, flush=True)
