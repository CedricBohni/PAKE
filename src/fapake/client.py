"""Interactive TCP client for the fuzzy aPAKE demo."""

import argparse
import json
import socket
import time

from fapake.ot import OTOffer, OTReply
from fapake.protocol import (DEFAULT_PARAMS, AuthResult, ClientSession, Params, ProtocolError,
                             parse_password)


class Client:
    """
       A client class to handle user registration and authentication with a server.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 65432, params: Params = DEFAULT_PARAMS) -> None:
        self.host = host
        self.port = port
        self.params = params

    def send_request(self, data: dict) -> str:
        """Send one JSON request on a fresh connection and return the response text."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(json.dumps(data).encode())
            return s.recv(61440).decode()

    def register(self, username: str, password: list[int]) -> str:
        return self.send_request({"action": "register", "username": username, "password": password})

    def authenticate(self, username: str, password: list[int]) -> AuthResult:
        """Run the full authentication against the server."""
        session = ClientSession(password, self.params)

        response = self.send_request({"action": "authenticate", "username": username})
        try:
            challenge = json.loads(response)
        except json.JSONDecodeError:
            raise ProtocolError(response) from None

        offer = OTOffer(challenge["x_0"], challenge["x_1"])
        while not session.done:
            index, v = session.next_query(offer)
            response = self.send_request({"action": "ot", "i": index, "v": v})
            try:
                data = json.loads(response)
            except json.JSONDecodeError:
                raise ProtocolError(response) from None
            offer = session.receive(OTReply(data["c0"], data["c1"], OTOffer(data["x0"], data["x1"])))

        return session.finish(challenge["cipher"])

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
            except ProtocolError as error:
                print(f"Error: {error}")
            except ConnectionError as error:
                print(f"Error: cannot reach server at {self.host}:{self.port} ({error})")
            print(f"Time taken for {title.lower()}: {time.perf_counter() - start:.6f} seconds\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuzzy aPAKE demo client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=65432)
    args = parser.parse_args()
    try:
        Client(args.host, args.port).start()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting")


if __name__ == "__main__":
    main()
