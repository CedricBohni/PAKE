import json
import socket
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import pytest

from fapake.client import Client
from fapake.ot import OTOffer, OTReply, RSAPublicKey
from fapake.protocol import (DEFAULT_PARAMS, DEMO_PARAMS, AuthChallenge, ClientSession,
                             ProtocolError)
from fapake.server import ConnectionState, Server, UserStore
from fapake.wire import recv_message, send_message

PASSWORD = [0, 1, 1, 0, 1, 1, 0, 0]


class KeyLog:
    """Collects the session keys the server derives, per username."""

    def __init__(self):
        self.keys = defaultdict(list)
        self.lock = threading.Lock()

    def __call__(self, username, key):
        with self.lock:
            self.keys[username].append(key)


def start_server(server):
    threading.Thread(target=server.start, daemon=True).start()
    assert server.ready.wait(10)
    return server.address


@pytest.fixture
def keylog():
    return KeyLog()


@pytest.fixture
def server(tmp_path, demo_key, keylog):
    return Server(port=0, params=DEMO_PARAMS, store=UserStore(tmp_path), ot_key=demo_key,
                  on_session_key=keylog)


@pytest.fixture
def client(server):
    host, port = start_server(server)
    return Client(host, port, DEMO_PARAMS, timeout=10)


def test_register_and_authenticate_over_tcp(client, keylog):
    assert client.register("alice", PASSWORD) == "Registration successful"
    result = client.authenticate("alice", PASSWORD)
    assert result.ok, result.reasons
    assert keylog.keys["alice"] == [result.session_key]


def test_one_bit_off_over_tcp(client, keylog):
    client.register("bob", PASSWORD)
    result = client.authenticate("bob", [1] + PASSWORD[1:])
    assert keylog.keys["bob"] == [result.session_key]


def test_two_bits_off_over_tcp(client, keylog):
    client.register("bob", PASSWORD)
    result = client.authenticate("bob", [1, 0] + PASSWORD[2:])
    assert not result.ok
    assert keylog.keys["bob"] != [result.session_key]


def test_unknown_user_over_tcp(client):
    with pytest.raises(ProtocolError, match="User not found"):
        client.authenticate("nobody", PASSWORD)


def test_concurrent_authentications(client, keylog):
    """Each connection has its own session, so parallel logins don't interfere."""
    users = [f"user{i}" for i in range(6)]
    for user in users:
        client.register(user, PASSWORD)

    with ThreadPoolExecutor(len(users)) as pool:
        results = list(pool.map(lambda user: client.authenticate(user, PASSWORD), users))

    for user, result in zip(users, results):
        assert result.ok, (user, result.reasons)
        assert keylog.keys[user] == [result.session_key]


def test_interleaved_sessions_on_two_connections(server, client, keylog):
    """Start two authentications, then run their OT rounds alternately."""
    client.register("carol", PASSWORD)
    client.register("dave", PASSWORD)
    conns, sessions, offers = [], [], []
    for user in ("carol", "dave"):
        sock = socket.create_connection(server.address, timeout=10)
        send_message(sock, {"action": "authenticate", "username": user})
        data = recv_message(sock)
        session = ClientSession(PASSWORD, DEMO_PARAMS)
        offers.append(session.begin(AuthChallenge(data["group"], data["cipher"],
                                                  OTOffer(data["x0"], data["x1"]),
                                                  RSAPublicKey(data["ot_n"], data["ot_e"]))))
        conns.append(sock)
        sessions.append(session)

    while not all(s.done for s in sessions):
        for i, (sock, session) in enumerate(zip(conns, sessions)):
            index, v = session.next_query(offers[i])
            send_message(sock, {"action": "ot", "i": index, "v": v})
            data = recv_message(sock)
            offers[i] = session.receive(OTReply(data["c0"], data["c1"], OTOffer(data["x0"], data["x1"])))
    for sock in conns:
        sock.close()

    carol, dave = (s.finish() for s in sessions)
    assert carol.ok and dave.ok
    assert keylog.keys["carol"] == [carol.session_key]
    assert keylog.keys["dave"] == [dave.session_key]


def test_ot_on_new_connection_has_no_session(server, client):
    """OT state is tied to the connection that started the authentication."""
    client.register("erin", PASSWORD)
    with socket.create_connection(server.address, timeout=10) as sock:
        send_message(sock, {"action": "authenticate", "username": "erin"})
        assert recv_message(sock)["ok"]
    with socket.create_connection(server.address, timeout=10) as sock:
        send_message(sock, {"action": "ot", "i": 0, "v": 5})
        assert recv_message(sock) == {"ok": False, "error": "No authentication in progress"}


def test_garbage_on_the_wire(server, client):
    with socket.create_connection(server.address, timeout=10) as sock:
        sock.sendall(b"\x00\x00\x00\x05{nope")
        assert recv_message(sock) == {"ok": False, "error": "invalid JSON"}
    # The server keeps serving other connections.
    client.register("frank", PASSWORD)


def test_group_mismatch_is_reported(tmp_path, demo_key, keylog):
    server = Server(port=0, params=DEMO_PARAMS, store=UserStore(tmp_path), ot_key=demo_key,
                    on_session_key=keylog)
    host, port = start_server(server)
    Client(host, port, DEMO_PARAMS).register("gina", PASSWORD)
    with pytest.raises(ProtocolError, match="server uses group 'demo'"):
        Client(host, port, DEFAULT_PARAMS).authenticate("gina", PASSWORD)


@pytest.mark.slow
def test_secure_group_over_tcp(tmp_path, secure_key, keylog):
    server = Server(port=0, store=UserStore(tmp_path), ot_key=secure_key, on_session_key=keylog)
    host, port = start_server(server)
    client = Client(host, port, timeout=60)
    client.register("henry", PASSWORD)
    result = client.authenticate("henry", PASSWORD[:7] + [1 - PASSWORD[7]])
    assert result.ok, result.reasons
    assert keylog.keys["henry"] == [result.session_key]


# ----------------------------------------------------------------- request handling without sockets

def request(server, message):
    return server.handle_request(message, ConnectionState())


def test_stored_file_has_no_password(server, tmp_path):
    request(server, {"action": "register", "username": "ivy", "password": PASSWORD})
    stored = json.loads((tmp_path / "ivy_file.json").read_text())
    assert set(stored) == {"group", "shares", "pw", "k"}


@pytest.mark.parametrize("message, error", [
    ({"action": "dance"}, "Invalid action or data"),
    ({"action": "register", "username": "x", "password": [1, 0]}, "Invalid registration data"),
    ({"action": "register", "username": "../evil", "password": PASSWORD}, "invalid username"),
    ({"action": "authenticate", "username": "ghost"}, "User not found"),
    ({"action": "authenticate"}, "invalid username"),
    ({"action": "ot", "i": 0, "v": 5}, "No authentication in progress"),
    ([1, 2, 3], "Invalid action or data"),
])
def test_bad_requests(server, message, error):
    assert request(server, message) == {"ok": False, "error": error}
