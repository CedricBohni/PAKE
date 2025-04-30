import json
import socket
import time

import cryptography

from utils.ot_protocol import receiver_ot
from mpyc.runtime import mpc
from utils.RSS import RobustSecretSharing
from utils.IC import decrypt

class Client:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port

    def send_request(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            payload = json.dumps(data)
            s.sendall(payload.encode())
            response = s.recv(61440).decode()
        return response

    def ot_protocol(self, password):
        print("=== OT ===")
        start_ot = time.perf_counter()
        shares = mpc.run(receiver_ot(password))
        end_ot = time.perf_counter()
        print("completed OT")
        print(f"Time taken for OT: {end_ot - start_ot:.6f} seconds")
        return shares

    def explicit_authentication(self, shares, key, response_data):
        print("=== Explicit Authentication ===")
        start_auth = time.perf_counter()
        shares_prime, pw_prime = decrypt(key, response_data)
        try:
            shares_prime, pw_prime = decrypt(key, response_data)
            for i, share in enumerate(shares):
                if share not in shares_prime[i]:
                    print("file has been tampered with")
                    return False

        except cryptography.exceptions.InvalidTag:
            print("wrong key for decryption: wrong password")
            return False

        end_auth = time.perf_counter()
        print(f"Time taken for explicit authentication: {end_auth - start_auth:.6f} seconds")
        return True

    def registration(self):
        print("=== User Registration ===")
        username = input("Enter username: ")
        password = [int(bit) for bit in input("Enter password bits: ")]

        start = time.perf_counter()

        print(f"your password is: {password}")

        registration_data = {
            "action": "register",
            "username": username,
            "password": password
        }

        response = self.send_request(registration_data)
        print(f"\nServer response: {response}")

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
        response_data = json.loads(response)
        print(f"\nServer response: {response_data}")

        shares = self.ot_protocol(password)

        print(f"your shares are: {shares}")

        key = self.reconstruct_secret(shares)

        if key is None:
            print("Reconstruction failed")
            return

        if self.explicit_authentication(shares, key, response_data):
            print(f"SESSION KEY: {key}")
        else:
            print("Authentication failed: Shares do not match.")

        end = time.perf_counter()
        print(f"Time taken for authentication: {end - start:.6f} seconds")

    def reconstruct_secret(self, shares):
        print("=== Reconstruction ===")
        start_recon = time.perf_counter()
        n = len(shares)
        RSS = RobustSecretSharing(n, 13, 2)
        key = RSS.reconstruct_secret(shares)
        print(f"Reconstructed key: {key}")
        end_recon = time.perf_counter()
        print(f"Time taken for reconstruction: {end_recon - start_recon:.6f} seconds")
        return key

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

if __name__ == '__main__':
    client = Client()
    client.start()