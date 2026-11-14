"""Download the fixture from a seed over the BitTorrent wire protocol.

    python3 -I deploy/k8s-test/leech.py HOST PORT TORRENT OUT

The test peer the Kubernetes end-to-end run seeds to. torrentd itself cannot
be one: it adds every torrent in upload mode and never requests a piece
(crates/torrentd-engine/src/policy.rs), so a second torrentd release would
sit at 0 % beside a working seed.

Connects to HOST:PORT, handshakes for the single-file v1 torrent TORRENT
(fixture.py's), declares interest, requests every block once the seed
unchokes it, checks every piece against the torrent's SHA-1 hashes, and
writes the payload to OUT. Exits non-zero, naming the cause, where the seed
closes the connection, answers for another torrent, sends a piece that fails
its hash, or has not delivered everything within TIMEOUT seconds.

Plain BEP 3 with no extensions: the reserved bits are zero, so the seed sends
no fast-extension or extended messages, and a choke drops every request still
outstanding, which this puts back in the queue.
"""

import hashlib
import secrets
import socket
import struct
import sys
import time
from collections import deque
from pathlib import Path

BLOCK = 16 * 1024
PIPELINE = 32
TIMEOUT = 120

CHOKE, UNCHOKE, INTERESTED, REQUEST, PIECE = 0, 1, 2, 6, 7


def decode(buf, i, spans=None):
    """The bencoded value at buf[i:], and the offset after it.

    Where spans is a dict, the byte span of each value of the dict at buf[i:]
    is recorded in it by key: the info dict's raw bytes are its infohash.
    """
    c = buf[i : i + 1]
    if c == b"i":
        end = buf.index(b"e", i)
        return int(buf[i + 1 : end]), end + 1
    if c == b"l":
        i += 1
        out = []
        while buf[i : i + 1] != b"e":
            value, i = decode(buf, i)
            out.append(value)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while buf[i : i + 1] != b"e":
            key, i = decode(buf, i)
            start = i
            out[key], i = decode(buf, i)
            if spans is not None:
                spans[key] = (start, i)
        return out, i + 1
    colon = buf.index(b":", i)
    start = colon + 1
    end = start + int(buf[i:colon])
    return buf[start:end], end


def recv_exact(sock, n, deadline):
    buf = bytearray()
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError
        sock.settimeout(left)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            sys.exit("leech: the seed closed the connection")
        buf += chunk
    return bytes(buf)


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: leech.py HOST PORT TORRENT OUT")
    host, port, torrent, out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

    meta = Path(torrent).read_bytes()
    spans = {}
    top, _ = decode(meta, 0, spans)
    info = top[b"info"]
    start, end = spans[b"info"]
    infohash = hashlib.sha1(meta[start:end]).digest()
    length = info[b"length"]
    piece_length = info[b"piece length"]
    hashes = info[b"pieces"]
    pieces = len(hashes) // 20

    def piece_size(p):
        return min(piece_length, length - p * piece_length)

    todo = deque(
        (p, off, min(BLOCK, piece_size(p) - off))
        for p in range(pieces)
        for off in range(0, piece_size(p), BLOCK)
    )
    blocks = len(todo)
    outstanding = {}
    received = 0
    data = bytearray(length)
    deadline = time.monotonic() + TIMEOUT
    choked = True

    try:
        sock = socket.create_connection((host, port), timeout=10)
        peer_id = b"-TK0001-" + secrets.token_hex(6).encode()
        sock.sendall(b"\x13BitTorrent protocol" + bytes(8) + infohash + peer_id)
        reply = recv_exact(sock, 68, deadline)
        if reply[:20] != b"\x13BitTorrent protocol":
            sys.exit(f"leech: not a BitTorrent handshake: {reply[:20]!r}")
        if reply[28:48] != infohash:
            sys.exit(f"leech: the seed answered for infohash {reply[28:48].hex()}, want {infohash.hex()}")
        sock.sendall(struct.pack(">IB", 1, INTERESTED))

        while received < blocks:
            while not choked and todo and len(outstanding) < PIPELINE:
                p, off, n = todo.popleft()
                outstanding[(p, off)] = n
                sock.sendall(struct.pack(">IBIII", 13, REQUEST, p, off, n))
            (size,) = struct.unpack(">I", recv_exact(sock, 4, deadline))
            if size == 0:
                continue
            msg = recv_exact(sock, size, deadline)
            if msg[0] == CHOKE:
                choked = True
                todo.extendleft((p, off, n) for (p, off), n in outstanding.items())
                outstanding.clear()
            elif msg[0] == UNCHOKE:
                choked = False
            elif msg[0] == PIECE:
                p, off = struct.unpack(">II", msg[1:9])
                block = msg[9:]
                if outstanding.get((p, off)) == len(block):
                    del outstanding[(p, off)]
                    at = p * piece_length + off
                    data[at : at + len(block)] = block
                    received += 1
            # Bitfield, have and anything else: nothing this needs.
    except TimeoutError:
        sys.exit(f"leech: {received} of {blocks} blocks within {TIMEOUT} s ({'choked' if choked else 'unchoked'})")
    except OSError as e:
        sys.exit(f"leech: {host}:{port}: {e}")

    for p in range(pieces):
        at = p * piece_length
        if hashlib.sha1(data[at : at + piece_size(p)]).digest() != hashes[p * 20 : p * 20 + 20]:
            sys.exit(f"leech: piece {p} fails its hash check")
    Path(out).write_bytes(data)
    print(f"leech: {length} bytes in {pieces} pieces, every hash checked")


if __name__ == "__main__":
    main()
