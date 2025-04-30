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
        if username:

            with open(f"userFiles/{username}_file.json", "r") as f:
                file = json.load(f)

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
