import json
import socket
import time
from utils.RSS_Exponent import RobustSecretSharing
from utils.IC import decrypt

class Client:
    """
       A client class to handle user registration and authentication with a server.
    """

    def __init__(self, host='127.0.0.1', port=65432):
        """
            Initializes the Client instance with the server's host and port.
        """

        self.host = host
        self.port = port
        self.RSS = RobustSecretSharing(8, 6, 1)
        # The following values are used for RSA encryption/decryptions in the oblivious transfer protocol.
        self.N = 12000991551859018265872407496869639382864790287669785722210322332355258447403853342474429805696877488833857305762518590969878052344745850541503850065903633
        self.e = 65537

    def send_request(self, data):
        """
            Sends a JSON-encoded request to the server and receives a response.ss
        """

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            payload = json.dumps(data)
            s.sendall(payload.encode())
            response = s.recv(61440).decode()
        return response

    def start(self):
        """
            Starts the client application.

            The method performs the following steps:
            - Displays a menu for the user to choose between registration, authentication, or exit.
            - Calls the appropriate method based on the user's choice.
            - Exits the application if the user selects an invalid option or chooses to exit.
        """

        while True:
            print("Choose an action:")
            print("1. Register")
            print("2. Authenticate")
            print("any: Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                self.registration()
            elif choice == '2':
                self.authentication()
            else:
                print("Exiting")
                break

    def registration(self):
        """
            Handles the registration process for a new user.

            The method performs the following steps:
            - Prompts the user to enter a username and an 8-bit password.
            - Sends the registration data to the server in JSON format.
            - Receives and displays the server's response.
            - Logs the time taken for the registration process.
        """

        print("=== User Registration ===")
        username = input("Enter username: ")
        password = [int(bit) for bit in input("Enter 8-bit password: ")]

        start = time.perf_counter()

        registration_data = {
            "action": "register",
            "username": username,
            "password": password
        }

        response = self.send_request(registration_data)
        print(f"\nServer registration response: {response}")

        end = time.perf_counter()
        print(f"Time taken for registration: {end - start:.6f} seconds")

    def authentication(self):
        """
            Handles user authentication by collecting a username and password, and verifying the response from the server.

            The method performs the following steps:
            - Sends authentication username to the server.
            - Receives and processes the server's response, getting the ciphertext.
            - Uses the receiver OT protocol to obtain shares of the password.
            - Reconstructs a secret key using the received shares.
            - Decrypts the server's response and verifies the password.
            - Generates a session key if authentication is successful.
        """


        print("=== User Authentication ===")
        username = input("Enter username: ")
        password = [int(bit) for bit in input("Enter 8-bit password: ")]

        start = time.perf_counter()

        auth_data = {
            "action": "authenticate",
            "username": username,
        }

        response = self.send_request(auth_data)

        if response == "User not found":
            print("Error: The user is not registered.")
            return

        response_json = json.loads(response)
        ciphertext = json.loads(response_json.get("cipher"))
        x_0 = response_json.get("x_0")
        x_1 = response_json.get("x_1")

        shares = self.oblivious_transfer(password, x_0, x_1)
        key = self.RSS.reconstruct_secret(shares)

        if key is None:
            print("Reconstruction failed")
            return

        decrypted_data = decrypt(key, ciphertext)

        cipher_shares = [tuple(pair) for pair in decrypted_data["shares"]]
        cipher_password = decrypted_data["pw"]

        close_passwords = passwords_with_hamming_distance_1(password)
        close_passwords_int_exponent = [self.RSS.Math.modular_generator_exponentiation(int("".join(map(str, pw)), 2)) for pw in close_passwords ]

        if not cipher_password in close_passwords_int_exponent:
            key = self.RSS.Math.generate_random_int()
            print("password is not in hamming distance")

        for i in range(8):
            passwd_bit = password[i]
            if shares[i] != cipher_shares[i][passwd_bit]:
                key = self.RSS.Math.generate_random_int()
                print("file has been tampered with")

        session_key = self.RSS.Math.pseudo_random_generator(key)

        print(f"SESSION KEY: {session_key}")

        end = time.perf_counter()
        print(f"Time taken for authentication: {end - start:.6f} seconds")

    def oblivious_transfer(self, password, first_x_0, first_x_1):
        """
            Performs the Oblivious Transfer protocol to obtain shares of the password.

            The method performs the following steps:
            - Initializes variables for the first x_0 and x_1 values.
            - Iterates over each bit of the password.
            - For each bit, generates a random integer k and computes v based on the password bit.
            - Sends an OT request to the server and receives a response containing new x_0, x_1, and cipher values.
            - Collects shares based on the received cipher values.
        """
        shares = []
        x0 = first_x_0
        x1 = first_x_1
        for i in range(8):

            k = self.RSS.Math.generate_random_int()
            if password[i] == 0:
                v = (x0 + pow(k, self.e, self.N)) % self.N
            else:
                v = (x1 + pow(k, self.e, self.N)) % self.N
            ot_data = {
                "action": "ot",
                "v": v,
                "i": i
            }
            response = json.loads(self.send_request(ot_data))

            if response == "Too many requests":
                print("Error: Too many requests")
                break

            x0 = response["x0"]
            x1 = response["x1"]
            cipher = response[f"c{password[i]}"]

            shares.append((cipher - k) % self.N)

        return shares

def passwords_with_hamming_distance_1(password):
    """
    Generates all possible passwords that have a Hamming distance of 1 from the given password.
    """

    result = [password]
    for i in range(len(password)):
        new_password = password[:]
        new_password[i] = 1 - new_password[i]
        result.append(new_password)
    return result

if __name__ == '__main__':
    client = Client()
    client.start()