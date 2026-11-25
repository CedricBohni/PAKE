import socket
import struct
import threading

import pytest

from fapake.wire import MAX_MESSAGE_SIZE, WireError, recv_message, send_message


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_round_trip(pair):
    a, b = pair
    message = {"action": "ot", "v": 2**3000 + 1, "text": "äöü"}
    send_message(a, message)
    assert recv_message(b) == message


def test_large_message_survives_tcp_splitting(pair):
    a, b = pair
    message = {"blob": "x" * 500_000}
    sender = threading.Thread(target=send_message, args=(a, message))
    sender.start()
    assert recv_message(b) == message
    sender.join()


def test_several_messages_in_one_stream(pair):
    a, b = pair
    for i in range(3):
        send_message(a, {"i": i})
    assert [recv_message(b) for _ in range(3)] == [{"i": 0}, {"i": 1}, {"i": 2}]


def test_message_split_into_single_bytes(pair):
    a, b = pair
    data = b'{"ok": true}'
    for byte in struct.pack(">I", len(data)) + data:
        a.send(bytes([byte]))
    assert recv_message(b) == {"ok": True}


def test_clean_close_returns_none(pair):
    a, b = pair
    a.close()
    assert recv_message(b) is None


def test_close_mid_message_raises(pair):
    a, b = pair
    a.sendall(struct.pack(">I", 100) + b'{"partial"')
    a.close()
    with pytest.raises(WireError, match="middle of a message"):
        recv_message(b)


def test_oversized_header_rejected(pair):
    a, b = pair
    a.sendall(struct.pack(">I", MAX_MESSAGE_SIZE + 1))
    with pytest.raises(WireError, match="too large"):
        recv_message(b)


def test_oversized_send_rejected(pair):
    a, _ = pair
    with pytest.raises(WireError, match="too large"):
        send_message(a, "x" * MAX_MESSAGE_SIZE)


def test_invalid_json_rejected(pair):
    a, b = pair
    a.sendall(struct.pack(">I", 5) + b"{nope")
    with pytest.raises(WireError, match="invalid JSON"):
        recv_message(b)
