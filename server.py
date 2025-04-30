import json
import socket
from utils.ot_protocol import sender_ot
from mpyc.runtime import mpc
from utils.RSS import RobustSecretSharing
from utils.Math import ModularArithmetic
from utils.IC import encrypt
import time

class Server:
    def __init__(self, host='127.0.0.1', port=65432):
        self.HOST = host
        self.PORT = port
        self.Math = ModularArithmetic()
        self.RSS = RobustSecretSharing(16, 13, 2)

    def start(self):
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
                self.send_response(conn, "Invalid action or data")
        except json.JSONDecodeError:
            self.send_response(conn, "Invalid JSON format")

    def handle_registration(self, conn, username, password, start):
        if username and password:
            print("=== User Registration ===")
            response = self.registration(username, password)
            self.send_response(conn, response)
            end = time.perf_counter()
            print(f"Time taken for registration: {end - start:.6f} seconds")
        else:
            self.send_response(conn, "Invalid registration data")

    def handle_authentication(self, conn, username, start):
        if username:
            try:
                print("=== User Authentication ===")
                response, shares, new_k = self.process_file(username)
                self.send_response(conn, response)
                print("cipher sent")
                print("OT shares:", shares)
                self.ot_procotocol(shares)
                print(f"SESSION KEY: {new_k}")
                end = time.perf_counter()
                print(f"Time taken for authentication: {end - start:.6f} seconds")
            except FileNotFoundError:
                self.send_response(conn, "User not found")
        else:
            self.send_response(conn, "Invalid authentication data")

    def ot_procotocol(self, shares):
        print("=== OT ===")
        start_ot = time.perf_counter()
        mpc.run(sender_ot(shares))
        end_ot = time.perf_counter()
        print("completed OT")
        print(f"Time taken for OT: {end_ot - start_ot:.6f} seconds")

    def send_response(self, conn, message):
        conn.sendall(message.encode())

    def registration(self, username, password):
        n = len(password)
        if n != 16:
            return "Registration failed: Password must be exactly 16 bits long"

        k = self.Math.generate_random_int()

        # exp_k = self.Math.modular_generator_exponentiation(k)
        # exp_p = self.Math.modular_generator_exponentiation(int(string_to_bitstring(password), 2))

        key_shares = self.RSS.generate_shares(k)

        shares = [None] * n

        print(f"check reconstruct: ", )

        for i, bit in enumerate(password):
            print(f"i:", i)
            print(f"bit:", bit)

            if bit == '1':
                shares[i] = (self.Math.generate_random_int(), key_shares[i])
            else:
                shares[i] = (key_shares[i], self.Math.generate_random_int())

        with open(f"userFiles/{username}_file.json", "w") as f:
            json.dump({"shares": shares, "P": ''.join(map(str, password)), "K": k}, f)

        print(f"Shares saved for user {username}")
        return "Registration successful"

    def process_file(self, username):
        print("=== processing file ===")
        start = time.perf_counter()

        with open(f"userFiles/{username}_file.json", "r") as f:
            file = json.load(f)

        shares = file["shares"]
        k = file["K"]
        pw = file["P"]

        k_prime = self.Math.generate_random_int()

        random_shares = self.RSS.generate_shares(k_prime)

        new_k = self.Math.modular_addition(k_prime, k)

        for i in range(len(shares)):
            shares[i] = (self.Math.modular_addition(shares[i][0], random_shares[i]),
                         self.Math.modular_addition(shares[i][1], random_shares[i]))
        print(f"The new key is: ", new_k)

        response = encrypt(new_k, shares, pw)

        end = time.perf_counter()
        print(f"Time taken for processing file: {end - start:.6f} seconds")

        return response, shares, new_k

if __name__ == "__main__":
    server = Server()
    server.start()
