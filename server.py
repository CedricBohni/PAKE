import json
import socket
from utils.ot_protocol import sender_ot
from mpyc.runtime import mpc
from utils.RSS import RobustSecretSharing
from utils.Math import ModularArithmetic
from utils.IC import encrypt
import time

class Server:
    """
       A server class to handle user registration and authentication.

       Attributes:
           HOST (str): The server's hostname or IP address.
           PORT (int): The server's port number.
           Math (ModularArithmetic): An instance of the ModularArithmetic class for mathematical operations.
           RSS (RobustSecretSharing): An instance of the RobustSecretSharing class for secret sharing operations.
   """

    def __init__(self, host='127.0.0.1', port=65432):
        """
            Initializes the Server instance with the server's host and port.

            Args:
                host (str): The server's hostname or IP address. Defaults to '127.0.0.1'.
                port (int): The server's port number. Defaults to 65432.
        """
        self.HOST = host
        self.PORT = port
        self.Math = ModularArithmetic()
        self.RSS = RobustSecretSharing(16, 13, 2)

    def start(self):
        """
            Starts the server to listen for incoming client connections.

            The method performs the following steps:
            - Binds the server to the specified host and port.
            - Listens for incoming client connections.
            - Accepts connections and handles client requests in a loop.
            - Measures and logs the time taken for each client request.

            This method runs indefinitely until the server is stopped.
        """

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            print(f"Server listening on {self.HOST}:{self.PORT}")
            while True:
                conn, addr = s.accept()
                with conn:
                    print('Connected by', addr)
                    start = time.perf_counter()
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        print("Received:", data.decode())
                        self.handle_request(conn, data, start)

    def handle_request(self, conn, data, start):
        """
            Handles incoming client requests by decoding the data, determining the action,
            and delegating to the appropriate handler method.

            Args:
                conn (socket): The client connection object.
                data (bytes): The raw data received from the client.
                start (float): The timestamp when the request was received.

            The method performs the following steps:
            - Decodes the JSON-encoded data from the client.
            - Extracts the action, username, and password from the data.
            - Delegates the request to either the registration or authentication handler based on the action.
            - Sends an error response if the action is invalid or the data is malformed.
        """

        try:
            message = json.loads(data.decode())
            action = message.get("action")
            username = message.get("username")
            password = message.get("password")

            actions = {
                "register": lambda: self.handle_registration(conn, username, password, start),
                "authenticate": lambda: self.handle_authentication(conn, username, start)
            }

            if action in actions:
                actions[action]()
            else:
                conn.sendall("Invalid action or data".encode())
        except json.JSONDecodeError:
            conn.sendall("Invalid JSON format".encode())

    def handle_registration(self, conn, username, password, start):
        """
        Handles the registration of a new user.

        Args:
            conn (socket): The client connection object.
            username (str): The username provided by the client.
            password (str): The password provided by the client (must be 16 characters long).
            start (float): The timestamp when the registration request was received.

        The method performs the following steps:
        - Validates the username and password.
        - Generates a random secret `k` and its shares using Robust Secret Sharing (RSS).
        - Structures the shares password-dependent for secure storage.
        - Saves the shares, password, and secret `k` to a file named after the username.
        - Sends a success or error response to the client.
        - Logs the time taken for the registration process.
        """

        if username and password and len(password) == 16:

            k = self.Math.generate_random_int()
            k_shares = self.RSS.generate_shares(k)

            shares = [(None, None)] * 16

            for i in range(16):
                password_bit = password[i]
                k_i = k_shares[i]
                r_i = self.Math.generate_random_int()
                if password_bit == 0:
                    shares[i] = (k_i, r_i)
                else:
                    shares[i] = (r_i, k_i)

            with open(f"userFiles/{username}_file.json", "w") as f:
                json.dump({"shares": shares, "pw": ''.join(map(str, password)), "k": k}, f)

            conn.sendall("Registration successful".encode())

            end = time.perf_counter()
            print(f"Time taken for registration: {end - start:.6f} seconds")

        else:
            conn.sendall("Invalid registration data".encode())

    def handle_authentication(self, conn, username, start):
        """
            Handles the authentication of a user.

            Args:
                conn (socket): The client connection object.
                username (str): The username provided by the client.
                start (float): The timestamp when the authentication request was received.

            The method performs the following steps:
            - Reads the user's stored file containing shares, password, and secret `k`.
            - Generates a random secret and its shares.
            - Randomizes the stored secret `k` and its shares using the random secret.
            - Encrypts the randomized shares and password using the randomized secret `k`.
            - Sends the encrypted data to the client.
            - Generates a session key using the randomized secret `k`.
            - Executes the sender oblivious transfer protocol.
            - Logs the session key and the time taken for the authentication process.
        """

        if username:

            try:
                with open(f"userFiles/{username}_file.json", "r") as f:
                    file = json.load(f)
            except FileNotFoundError:
                conn.sendall("User not found".encode())
                return

            shares = file["shares"]
            k = file["k"]
            password = file["pw"]

            random_secret = self.Math.generate_random_int()
            random_secret_shares = self.RSS.generate_shares(random_secret)

            randomized_k = self.Math.modular_addition(k, random_secret)

            randomized_shares = [(None, None)] * 16
            for i in range(16):
                k_i = shares[i][0]
                r_i = shares[i][1]
                randomized_shares[i] = (self.Math.modular_addition(k_i, random_secret_shares[i]),
                                        self.Math.modular_addition(r_i, random_secret_shares[i]))


            json_shares = [list(pair) for pair in randomized_shares]
            data = json.dumps({
                "shares": json_shares,
                "pw": password
            })

            ciphertext = encrypt(randomized_k, data)

            conn.sendall(ciphertext.encode())

            session_key = self.Math.pseudo_random_generator(randomized_k)

            mpc.run(sender_ot(randomized_shares))

            print(f"SESSION KEY: {session_key}")

            end = time.perf_counter()
            print(f"Time taken for authentication: {end - start:.6f} seconds")

        else:
         conn.sendall("Invalid authentication data".encode())

if __name__ == "__main__":
    server = Server()
    server.start()
