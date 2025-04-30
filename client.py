import json
import socket
import time
from utils.ot_protocol import receiver_ot
from mpyc.runtime import mpc
from utils.RSS import RobustSecretSharing
from utils.IC import decrypt

class Client:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.RSS = RobustSecretSharing(16, 13, 2)

    def send_request(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            payload = json.dumps(data)
            s.sendall(payload.encode())
            response = s.recv(61440).decode()
        return response

    def start(self):
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

        print("=== User Registration ===")
        username = input("Enter username: ")
        password = [int(bit) for bit in input("Enter password bits: ")]

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

        print("=== User Authentication ===")
        username = input("Enter username: ")
        password = [int(bit) for bit in input("Enter password bits: ")]

        start = time.perf_counter()

        auth_data = {
            "action": "authenticate",
            "username": username,
        }

        response = self.send_request(auth_data)
        ciphertext = json.loads(response)
        print(f"\nServer response: {ciphertext}")

        shares = mpc.run(receiver_ot(password))

        key = self.RSS.reconstruct_secret(shares)

        if key is None:
            print("Reconstruction failed")
            return

        decrypted_data = decrypt(key, ciphertext)

        cipher_shares = [tuple(pair) for pair in decrypted_data["shares"]]
        cipher_password = [int(bit) for bit in decrypted_data["pw"]]

        hamming_distance = sum(p1 != p2 for p1, p2 in zip(password, cipher_password))

        if hamming_distance > 2:
            key = self.RSS.Math.generate_random_int()
            print("password is not in hamming distance")

        else:
            for i in range(16):
                passwd_bit = password[i]
                if shares[i] != cipher_shares[i][passwd_bit]:
                    key = self.RSS.Math.generate_random_int()
                    print("file has been tampered with")

        session_key = self.RSS.Math.pseudo_random_generator(key)

        print(f"SESSION KEY: {session_key}")

        end = time.perf_counter()
        print(f"Time taken for authentication: {end - start:.6f} seconds")

if __name__ == '__main__':
    client = Client()
    client.start()