"""Interactive TCP client for the fuzzy aPAKE demo."""

import argparse
import socket
import time

from fapake.ot import OTOffer, OTReply, RSAPublicKey
from fapake.protocol import (
    DEFAULT_PARAMS,
    DEMO_PARAMS,
    AuthChallenge,
    AuthResult,
    ClientSession,
    Params,
    ProtocolError,
    parse_password,
)
from fapake.wire import WireError, recv_message, send_message


class Client:
    """
    A client class to handle user registration and authentication with a server.
    """

    def __init__(
        self, host: str = "127.0.0.1", port: int = 65432, params: Params = DEFAULT_PARAMS, timeout: float = 30.0
    ) -> None:
        self.host = host
        self.port = port
        self.params = params
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        return socket.create_connection((self.host, self.port), timeout=self.timeout)

    @staticmethod
    def _request(sock: socket.socket, message: dict) -> dict:
        """Send one request and return the response, raising ProtocolError on failure."""
        send_message(sock, message)
        response = recv_message(sock)
        if not isinstance(response, dict):
            raise ProtocolError("server closed the connection")
        if not response.get("ok"):
            raise ProtocolError(response.get("error", "unknown server error"))
        return response

    def register(self, username: str, password: list[int]) -> str:
        with self._connect() as sock:
            response = self._request(sock, {"action": "register", "username": username, "password": password})
        return response["message"]

    def authenticate(self, username: str, password: list[int]) -> AuthResult:
        """Run the full authentication against the server on one connection."""
        session = ClientSession(password, self.params)
        with self._connect() as sock:
            data = self._request(sock, {"action": "authenticate", "username": username})
            offer = session.begin(
                AuthChallenge(
                    group=data["group"],
                    cipher=data["cipher"],
                    offer=OTOffer(data["x0"], data["x1"]),
                    ot_key=RSAPublicKey(data["ot_n"], data["ot_e"]),
                )
            )

            while not session.done:
                index, v = session.next_query(offer)
                data = self._request(sock, {"action": "ot", "i": index, "v": v})
                offer = session.receive(OTReply(data["c0"], data["c1"], OTOffer(data["x0"], data["x1"])))

        return session.finish()

    def start(self) -> None:
        """Interactive menu."""
        while True:
            print("Choose an action:")
            print("1. Register")
            print("2. Authenticate")
            print("any: Exit")
            choice = input("Enter your choice: ")

            if choice not in ("1", "2"):
                print("Exiting")
                break

            title = "Registration" if choice == "1" else "Authentication"
            print(f"=== User {title} ===")
            username = input("Enter username: ")
            try:
                password = parse_password(input(f"Enter {self.params.n}-bit password: "), self.params.n)
            except ProtocolError as error:
                print(f"Error: {error}\n")
                continue

            start = time.perf_counter()
            try:
                if choice == "1":
                    print(f"\nServer registration response: {self.register(username, password)}")
                else:
                    result = self.authenticate(username, password)
                    for reason in result.reasons:
                        print(reason)
                    print(f"SESSION KEY: {result.session_key}")
            except (ProtocolError, WireError) as error:
                print(f"Error: {error}")
            except OSError as error:
                print(f"Error: cannot reach server at {self.host}:{self.port} ({error})")
            print(f"Time taken for {title.lower()}: {time.perf_counter() - start:.6f} seconds\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuzzy aPAKE demo client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    parser.add_argument("--demo", action="store_true", help="use the tiny insecure demo group (must match the server)")
    args = parser.parse_args()
    try:
        Client(args.host, args.port, DEMO_PARAMS if args.demo else DEFAULT_PARAMS).start()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting")


if __name__ == "__main__":
    main()
