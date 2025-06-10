import json
import socket
from utils.RSS_Exponent import RobustSecretSharing
from utils.Math import ModularArithmetic
from utils.IC import encrypt
import time

class Server:
    """
       A server class to handle user registration and authentication
   """

    def __init__(self, host='127.0.0.1', port=65432):
        """
            Initializes the Server instance with the specified host and port,
            and sets up the necessary cryptographic and mathematical components.
        """
        self.HOST = host
        self.PORT = port
        self.Math = ModularArithmetic()
        self.RSS = RobustSecretSharing(8, 6, 1)
        # RSA parameters for oblivious transfer protocol
        self.N = 12000991551859018265872407496869639382864790287669785722210322332355258447403853342474429805696877488833857305762518590969878052344745850541503850065903633
        self.e = 65537
        self.d = 11862920727285087512672416724441244612053186889941738688709451327600755420573868763412620915039546779273239567721613654909753857882486728158879371802110993
        # Initialize x0 and x1 for oblivious transfer
        self.x0 = 0
        self.x1 = 0
        # temporary shares for oblivious transfer and tracking requests
        self.temp_shares = [(None, None)] * 8
        self.request_counter = 0

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

            Steps:
            1. Decode the JSON-encoded data from the client.
            2. Extract the action, username, password, and other relevant fields.
            3. Delegate the request to the appropriate handler based on the action.
            4. Send an error response if the action is invalid or the data is malformed.
        """

        try:
            message = json.loads(data.decode())
            action = message.get("action")
            username = message.get("username")
            password = message.get("password")
            v = message.get("v")
            bit = message.get("i")

            actions = {
                "register": lambda: self.handle_registration(conn, username, password, start),
                "authenticate": lambda: self.handle_authentication(conn, username, start),
                "ot": lambda: self.handle_ot(conn, v, bit)
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

        if username and password and len(password) == 8:

            k = self.Math.generate_random_int(sub=True)
            print("Generated secret k:", k)
            k_shares = self.RSS.generate_shares(k)

            k_exponent = self.Math.modular_generator_exponentiation(k)
            print(password)
            password_int = int("".join(map(str, password)), 2)
            print("password:", password_int)
            pw_exponent = self.Math.modular_generator_exponentiation(password_int)

            shares = [(None, None)] * 8
            for i in range(8):
                password_bit = password[i]
                k_i = self.Math.modular_generator_exponentiation(k_shares[i])
                r_i = self.Math.modular_generator_exponentiation(self.Math.generate_random_int(sub=True))
                if password_bit == 0:
                    shares[i] = (k_i, r_i)
                else:
                    shares[i] = (r_i, k_i)

            with open(f"userFiles/{username}_file.json", "w") as f:
                json.dump({"shares": shares, "pw": pw_exponent, "k": k_exponent}, f)

            conn.sendall("Registration successful".encode())

            end = time.perf_counter()
            print(f"Time taken for registration: {end - start:.6f} seconds")

        else:
            conn.sendall("Invalid registration data".encode())

    def handle_authentication(self, conn, username, start):
        """
            Handles the authentication of a user.

            The method performs the following steps:
            - Reads the user's stored file containing exponentiated shares, password, and secret.
            - Generates a random secret and its shares.
            - Randomizes the stored secret and its shares using the random secret.
            - Encrypts the randomized shares and password using the randomized secret.
            - Sends the encrypted data to the client.
            - Generates a session key using the randomized secret.
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
            k_exponent = file["k"]
            password_exponent = file["pw"]

            random_secret = self.Math.generate_random_int(sub=True)
            random_secret_shares = self.RSS.generate_shares(random_secret)

            random_exponent = self.Math.modular_generator_exponentiation(random_secret)

            randomized_k_exponent = self.Math.modular_multiplication(k_exponent, random_exponent)

            randomized_shares = [(None, None)] * 8
            for i in range(8):
                zero_i = shares[i][0]
                one_i = shares[i][1]
                exponent_share = self.Math.modular_generator_exponentiation(random_secret_shares[i])
                randomized_shares[i] = (self.Math.modular_multiplication(zero_i, exponent_share),
                                        self.Math.modular_multiplication(one_i, exponent_share))


            json_shares = [list(pair) for pair in randomized_shares]
            data = json.dumps({
                "shares": json_shares,
                "pw": password_exponent
            })

            self.x0 = self.Math.generate_random_int()
            self.x1 = self.Math.generate_random_int()

            ciphertext = json.dumps({
                "cipher": encrypt(randomized_k_exponent, data),
                "x_0": self.x0,
                "x_1": self.x1
            })

            self.request_counter = 0
            self.temp_shares = randomized_shares

            conn.sendall(ciphertext.encode())

            session_key = self.Math.pseudo_random_generator(randomized_k_exponent)

            print(f"SESSION KEY: {session_key}")

            end = time.perf_counter()
            print(f"Time taken for authentication: {end - start:.6f} seconds")

        else:
         conn.sendall("Invalid authentication data".encode())

    def handle_ot(self, conn, v, bit):
        """
            Handles the Oblivious Transfer (OT) request from the client.

            The method performs the following steps:
            - Validates the bit index and checks if the request limit has been reached.
            - Retrieves the share tuple based on the provided bit.
            - Computes the cipher values using the provided value `v` and the server's x0 and x1.
            - Updates x0 and x1 with new random integers.
            - Sends the computed cipher values and updated x0, x1 to the client.
        """
        if self.request_counter >= 8:
            conn.sendall("Too many requests".encode())
            return

        share_tuple = self.temp_shares[bit]

        k0 = pow((v - self.x0), self.d, self.N)
        k1 = pow((v - self.x1), self.d, self.N)

        cipher0 = (share_tuple[0] + k0) % self.N
        cipher1 = (share_tuple[1] + k1) % self.N

        self.x0 = self.Math.generate_random_int()
        self.x1 = self.Math.generate_random_int()

        data = json.dumps({
            "c0": cipher0,
            "c1": cipher1,
            "x0": self.x0,
            "x1": self.x1,
        })

        conn.sendall(data.encode())

        self.request_counter += 1
        if self.request_counter >= 8:
            self.temp_shares = []
        return

if __name__ == "__main__":
    server = Server()
    server.start()
