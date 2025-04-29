import json
import socket
from utils import string_to_bitstring
from ot_protocol import sender_ot
from mpyc.runtime import mpc
from RSS import RobustSecretSharing
from Math import ModularArithmetic
from IC import encrypt
import time

class Server:
    def __init__(self, host='127.0.0.1', port=65432):
        self.HOST = host
        self.PORT = port
        self.Math = ModularArithmetic()

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
            self.registration(username, password)
            self.send_response(conn, "Registration successful")
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
        bit_password = string_to_bitstring(password)

        print(f"bit_password: {bit_password}")

        n = len(bit_password)
        t = n - 2 * 8 - 1  # -1 necessary for the reed solomon codes to work
        k = self.Math.generate_random_int()

        exp_k = self.Math.modular_generator_exponentiation(k)
        exp_p = self.Math.modular_generator_exponentiation(int(string_to_bitstring(password), 2))

        RSS = RobustSecretSharing(n, t, 0)
        key_shares = RSS.generate_shares(k)

        shares = [None] * n

        for i, bit in enumerate(bit_password):
            if bit == '1':
                shares[i] = (self.Math.generate_random_int(), key_shares[i])
            else:
                shares[i] = (key_shares[i], self.Math.generate_random_int())

        with open(f"{username}_file.json", "w") as f:
            json.dump({"shares": shares, "P": bit_password, "K": k}, f)

        print(f"Shares saved for user {username}")

    def process_file(self, username):
        print("=== processing file ===")
        start = time.perf_counter()

        with open(f"{username}_file.json", "r") as f:
            file = json.load(f)

        shares = file["shares"]
        k = file["K"]
        pw = file["P"]

        k_prime = self.Math.generate_random_int()
        new_k = self.Math.modular_addition(k_prime, k)
        n = len(shares)
        t = n - 2 * 8 - 1

        RSS = RobustSecretSharing(n, t, 0)
        random_shares = RSS.generate_shares(k_prime)
        for i in range(n):
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
