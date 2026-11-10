"""Write the payload and .torrent the Kubernetes end-to-end run seeds.

    python3 -I deploy/k8s-test/fixture.py DIR

Writes DIR/k8s-e2e.bin, a 4 MiB payload derived from a fixed seed, and
DIR/k8s-e2e.torrent, a single-file v1 torrent of it with no tracker, then
prints the torrent's v1 infohash and the payload's size on one line. The same
bytes come out on every run, so a failure names the same infohash each time.
"""

import hashlib
import sys
from pathlib import Path

NAME = "k8s-e2e.bin"
PIECE_LENGTH = 256 * 1024
PIECES = 16


def bencode(value):
    if isinstance(value, int):
        return b"i%de" % value
    if isinstance(value, bytes):
        return b"%d:%s" % (len(value), value)
    if isinstance(value, str):
        return bencode(value.encode())
    if isinstance(value, dict):
        # Keys sorted as raw bytes, as BEP 3 requires.
        items = sorted((k.encode() if isinstance(k, str) else k, v) for k, v in value.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError(f"cannot bencode {type(value).__name__}")


def payload():
    # A SHA-256 chain: every piece differs, so a piece served from the wrong
    # offset fails its hash check rather than passing by coincidence.
    out = bytearray()
    block = b"torrentd k8s end-to-end fixture"
    while len(out) < PIECE_LENGTH * PIECES:
        block = hashlib.sha256(block).digest()
        out += block
    return bytes(out[: PIECE_LENGTH * PIECES])


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: fixture.py DIR")
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    data = payload()
    pieces = b"".join(
        hashlib.sha1(data[i : i + PIECE_LENGTH]).digest() for i in range(0, len(data), PIECE_LENGTH)
    )
    info = {"length": len(data), "name": NAME, "piece length": PIECE_LENGTH, "pieces": pieces}
    (out / NAME).write_bytes(data)
    (out / "k8s-e2e.torrent").write_bytes(bencode({"created by": "torrentd k8s-test", "info": info}))
    print(hashlib.sha1(bencode(info)).hexdigest(), len(data))


if __name__ == "__main__":
    main()
