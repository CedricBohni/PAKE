"""TCP server for the fuzzy aPAKE demo.

Messages are length-prefixed JSON (see wire.py). Every response carries "ok".
An authentication runs on a single connection, so each connection has its own session
and several clients can authenticate at the same time.

    {"action": "register", "username", "password": [bits]}
        -> {"ok": true, "message": "Registration successful"}
    {"action": "authenticate", "username"}
        -> {"ok": true, "group", "cipher", "x0", "x1", "ot_n", "ot_e"}
    {"action": "ot", "i": int, "v": int}         (same connection, n times)
        -> {"ok": true, "c0", "c1", "x0", "x1"}
    any failure
        -> {"ok": false, "error": str}
"""

import argparse
import json
import re
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fapake.ot import RSAKeyPair
from fapake.protocol import (DEFAULT_PARAMS, DEMO_PARAMS, Params, ProtocolError, ServerSession,
                             UserRecord, register, validate_password)
from fapake.wire import WireError, recv_message, send_message

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class UserStore:
    """Stores one JSON record per user in a directory."""

    def __init__(self, directory: str | Path = "userFiles") -> None:
        self.directory = Path(directory)
        self._lock = threading.Lock()

    def _path(self, username: object) -> Path:
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise ProtocolError("invalid username")
        return self.directory / f"{username}_file.json"

    def save(self, username: str, record: UserRecord) -> None:
        path = self._path(username)
        with self._lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record.to_dict()))

    def load(self, username: str) -> UserRecord | None:
        path = self._path(username)
        with self._lock:
            if not path.exists():
                return None
            return UserRecord.from_dict(json.loads(path.read_text()))


@dataclass
class ConnectionState:
    """Per-connection state: the authentication in progress, if any."""
    session: ServerSession | None = None


def _print_session_key(username: str, key: str) -> None:
    print(f"SESSION KEY ({username}): {key}")


class Server:
    """
       A server class to handle user registration and authentication
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 65432, params: Params = DEFAULT_PARAMS,
                 store: UserStore | None = None, ot_key: RSAKeyPair | None = None,
                 on_session_key: Callable[[str, str], None] = _print_session_key) -> None:
        self.host = host
        self.port = port
        self.params = params
        self.store = store or UserStore()
        # One RSA key per server run, generated fresh; never stored on disk.
        self.ot_key = ot_key or params.generate_ot_key()
        self.on_session_key = on_session_key
        self.address: tuple[str, int] | None = None
        self.ready = threading.Event()

    def start(self) -> None:
        """Listen for connections and serve each one in its own thread until interrupted."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            self.address = s.getsockname()
            self.ready.set()
            print(f"Server listening on {self.address[0]}:{self.address[1]} "
                  f"(group {self.params.group.name}, OT key {self.ot_key.N.bit_length()} bits)")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.serve_connection, args=(conn, addr), daemon=True).start()

    def serve_connection(self, conn: socket.socket, addr: object = None) -> None:
        state = ConnectionState()
        start = time.perf_counter()
        with conn:
            try:
                while (message := recv_message(conn)) is not None:
                    send_message(conn, self.handle_request(message, state))
            except WireError as error:
                try:
                    send_message(conn, {"ok": False, "error": str(error)})
                except OSError:
                    pass
            except OSError:
                pass  # client went away
        print(f"{addr}: connection handled in {time.perf_counter() - start:.6f} seconds")

    def handle_request(self, message: object, state: ConnectionState) -> dict:
        """Handle one decoded request and return the response."""
        if not isinstance(message, dict):
            return {"ok": False, "error": "Invalid action or data"}
        handlers = {
            "register": self.handle_registration,
            "authenticate": self.handle_authentication,
            "ot": self.handle_ot,
        }
        handler = handlers.get(message.get("action"))
        if handler is None:
            return {"ok": False, "error": "Invalid action or data"}
        try:
            return {"ok": True, **handler(message, state)}
        except ProtocolError as error:
            return {"ok": False, "error": str(error)}

    def handle_registration(self, message: dict, state: ConnectionState) -> dict:
        username = message.get("username")
        try:
            password = validate_password(message.get("password"), self.params.n)
        except ProtocolError:
            raise ProtocolError("Invalid registration data") from None
        self.store.save(username, register(password, self.params))
        print(f"Registered {username}")
        return {"message": "Registration successful"}

    def handle_authentication(self, message: dict, state: ConnectionState) -> dict:
        username = message.get("username")
        record = self.store.load(username)
        if record is None:
            raise ProtocolError("User not found")

        state.session = ServerSession(record, self.ot_key, self.params)
        challenge = state.session.challenge()
        self.on_session_key(username, state.session.session_key)
        return {"group": challenge.group, "cipher": challenge.cipher,
                "x0": challenge.offer.x0, "x1": challenge.offer.x1,
                "ot_n": challenge.ot_key.N, "ot_e": challenge.ot_key.e}

    def handle_ot(self, message: dict, state: ConnectionState) -> dict:
        if state.session is None:
            raise ProtocolError("No authentication in progress")
        reply = state.session.respond_ot(message.get("i"), message.get("v"))
        return {"c0": reply.c0, "c1": reply.c1, "x0": reply.next_offer.x0, "x1": reply.next_offer.x1}


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuzzy aPAKE demo server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    parser.add_argument("--store", default="userFiles", help="directory for user records")
    parser.add_argument("--demo", action="store_true",
                        help="use the tiny insecure demo group (fast, readable numbers)")
    args = parser.parse_args()
    params = DEMO_PARAMS if args.demo else DEFAULT_PARAMS
    print(f"Generating {params.ot_key_bits}-bit RSA key for oblivious transfer...")
    try:
        Server(args.host, args.port, params, store=UserStore(args.store)).start()
    except KeyboardInterrupt:
        print("\nServer stopped")


if __name__ == "__main__":
    main()
