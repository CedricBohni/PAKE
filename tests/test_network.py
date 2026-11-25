import json
import threading

import pytest

from fapake.client import Client
from fapake.protocol import ProtocolError
from fapake.server import Server, UserStore

PASSWORD = [0, 1, 1, 0, 1, 1, 0, 0]


@pytest.fixture
def server(tmp_path):
    return Server(port=0, store=UserStore(tmp_path))


@pytest.fixture
def running(server):
    threading.Thread(target=server.start, daemon=True).start()
    assert server.ready.wait(5)
    host, port = server.address
    return server, Client(host, port)


def test_register_and_authenticate_over_tcp(running):
    server, client = running
    assert client.register("alice", PASSWORD) == "Registration successful"

    result = client.authenticate("alice", PASSWORD)
    assert result.ok, result.reasons
    assert result.session_key == server.session.session_key


def test_one_bit_off_over_tcp(running):
    server, client = running
    client.register("bob", PASSWORD)
    result = client.authenticate("bob", [1] + PASSWORD[1:])
    assert result.session_key == server.session.session_key


def test_unknown_user_over_tcp(running):
    _, client = running
    with pytest.raises(ProtocolError, match="User not found"):
        client.authenticate("nobody", PASSWORD)


def request(server, message):
    return server.handle_request(json.dumps(message).encode())


def test_stored_file_has_no_password(server, tmp_path):
    request(server, {"action": "register", "username": "carol", "password": PASSWORD})
    stored = json.loads((tmp_path / "carol_file.json").read_text())
    assert set(stored) == {"shares", "pw", "k"}


@pytest.mark.parametrize("message, expected", [
    ({"action": "dance"}, "Invalid action or data"),
    ({"action": "register", "username": "x", "password": [1, 0]}, "Invalid registration data"),
    ({"action": "register", "username": "../evil", "password": PASSWORD}, "invalid username"),
    ({"action": "authenticate", "username": "ghost"}, "User not found"),
    ({"action": "ot", "i": 0, "v": 5}, "No authentication in progress"),
    ([1, 2, 3], "Invalid action or data"),
])
def test_bad_requests(server, message, expected):
    assert request(server, message) == expected


def test_invalid_json(server):
    assert server.handle_request(b"{not json") == "Invalid JSON format"
