"""TCP server for the fuzzy aPAKE demo.

Wire format: one JSON object per request, one response per request.
    {"action": "register", "username": str, "password": [bits]}  -> "Registration successful"
    {"action": "authenticate", "username": str}                  -> {"cipher", "x_0", "x_1"}
    {"action": "ot", "i": int, "v": int}                         -> {"c0", "c1", "x0", "x1"}
"""

import argparse
import json
import re
import socket
import threading
import time
from pathlib import Path

from fapake.protocol import (DEFAULT_PARAMS, Params, ProtocolError, ServerSession, UserRecord,
                             register, validate_password)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class UserStore:
    """Stores one JSON record per user in a directory."""

    def __init__(self, directory: str | Path = "userFiles") -> None:
        self.directory = Path(directory)

    def _path(self, username: str) -> Path:
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise ProtocolError("invalid username")
        return self.directory / f"{username}_file.json"

    def save(self, username: str, record: UserRecord) -> None:
        path = self._path(username)
        self.directory.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record.to_dict()))

    def load(self, username: str) -> UserRecord | None:
        path = self._path(username)
        if not path.exists():
            return None
        return UserRecord.from_dict(json.loads(path.read_text()))


class Server:
    """
       A server class to handle user registration and authentication
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 65432, params: Params = DEFAULT_PARAMS,
                 store: UserStore | None = None) -> None:
        self.host = host
        self.port = port
        self.params = params
        self.store = store or UserStore()
        # One authentication at a time, as in the original design.
        self.session: ServerSession | None = None
        self.address: tuple[str, int] | None = None
        self.ready = threading.Event()

    def start(self) -> None:
        """Listen for connections and serve requests until interrupted."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            self.address = s.getsockname()
            self.ready.set()
            print(f"Server listening on {self.address[0]}:{self.address[1]}")
            while True:
                conn, addr = s.accept()
                with conn:
                    start = time.perf_counter()
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.sendall(self.handle_request(data).encode())
                    print(f"{addr}: handled in {time.perf_counter() - start:.6f} seconds")

    def handle_request(self, data: bytes) -> str:
        """Decode one request and return the response text."""
        try:
            message = json.loads(data.decode())
            if not isinstance(message, dict):
                raise ProtocolError("Invalid action or data")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "Invalid JSON format"
        except ProtocolError as error:
            return str(error)

        handlers = {
            "register": self.handle_registration,
            "authenticate": self.handle_authentication,
            "ot": self.handle_ot,
        }
        handler = handlers.get(message.get("action"))
        if handler is None:
            return "Invalid action or data"
        try:
            return handler(message)
        except ProtocolError as error:
            return str(error)

    def handle_registration(self, message: dict) -> str:
        username = message.get("username")
        try:
            password = validate_password(message.get("password"), self.params.n)
        except ProtocolError:
            return "Invalid registration data"
        self.store.save(username, register(password, self.params))
        print(f"Registered {username}")
        return "Registration successful"

    def handle_authentication(self, message: dict) -> str:
        username = message.get("username")
        record = self.store.load(username)
        if record is None:
            return "User not found"

        self.session = ServerSession(record, self.params)
        challenge = self.session.challenge()
        print(f"SESSION KEY ({username}): {self.session.session_key}")
        return json.dumps({"cipher": challenge.cipher, "x_0": challenge.offer.x0, "x_1": challenge.offer.x1})

    def handle_ot(self, message: dict) -> str:
        if self.session is None:
            return "No authentication in progress"
        v, index = message.get("v"), message.get("i")
        if not isinstance(v, int):
            return "Invalid action or data"
        reply = self.session.respond_ot(index, v)
        return json.dumps({"c0": reply.c0, "c1": reply.c1,
                           "x0": reply.next_offer.x0, "x1": reply.next_offer.x1})


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuzzy aPAKE demo server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    parser.add_argument("--store", default="userFiles", help="directory for user records")
    args = parser.parse_args()
    try:
        Server(args.host, args.port, store=UserStore(args.store)).start()
    except KeyboardInterrupt:
        print("\nServer stopped")


if __name__ == "__main__":
    main()
