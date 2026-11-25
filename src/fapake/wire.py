"""Length-prefixed JSON messages over a stream socket.

Each message is a 4-byte big-endian length followed by that many bytes of UTF-8 JSON.
This keeps message boundaries intact no matter how TCP splits or merges the data.
"""

import json
import socket
import struct

MAX_MESSAGE_SIZE = 1 << 20  # 1 MiB
_HEADER = struct.Struct(">I")


class WireError(Exception):
    """The peer sent something that is not a valid framed message."""


def send_message(sock: socket.socket, message: object) -> None:
    data = json.dumps(message).encode()
    if len(data) > MAX_MESSAGE_SIZE:
        raise WireError("message too large")
    sock.sendall(_HEADER.pack(len(data)) + data)


def recv_message(sock: socket.socket) -> object | None:
    """Return the next message, or None if the peer closed the connection cleanly."""
    header = _recv_exact(sock, _HEADER.size, eof_ok=True)
    if header is None:
        return None
    (length,) = _HEADER.unpack(header)
    if length > MAX_MESSAGE_SIZE:
        raise WireError("message too large")
    body = _recv_exact(sock, length, eof_ok=False)
    try:
        return json.loads(body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WireError("invalid JSON") from error


def _recv_exact(sock: socket.socket, size: int, eof_ok: bool) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            if eof_ok and not buffer:
                return None
            raise WireError("connection closed in the middle of a message")
        buffer += chunk
    return bytes(buffer)
