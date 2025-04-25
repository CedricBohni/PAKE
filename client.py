import json
import socket
from utils import string_to_bitstring
from ot_protocol import receiver_ot
from mpyc.runtime import mpc
from crypto_utils import reconstruct_secret, decrypt, random_int
import time

HOST = '127.0.0.1'
PORT = 65433

# Client that sends the registration data to the server in a json format
def registration():
    print("=== User Registration ===")
    username = input("Enter username: ")
    password = input("Enter password: ")

    start = time.perf_counter()

    registration_data = {
        "action": "register",
        "username": username,
        "password": password
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        payload = json.dumps(registration_data)
        s.sendall(payload.encode())
        response = s.recv(1024).decode()
        print(f"\nServer response: {response}")

    end = time.perf_counter()

    print(f"Time taken for registration: {end - start:.6f} seconds")

def authentication():
    print("=== User Authentication ===")
    username = input("Enter username: ")
    password = [int(bit) for bit in string_to_bitstring(input("Enter password: "))]

    start = time.perf_counter()

    auth_data = {
        "action": "authenticate",
        "username": username,
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        payload = json.dumps(auth_data)
        s.sendall(payload.encode())
        response = s.recv(61440).decode()
        # response = b""
        # while True:
        #     chunk = s.recv(4096)
        #     print(f"chunk: {chunk}")
        #     if not chunk:
        #         break
        #     response += chunk
        # response_data = json.loads(response.decode())
        response_data = json.loads(response)
        print(f"\nServer response: {response_data}")

    print("=== OT ===")
    start_ot = time.perf_counter()
    shares = mpc.run(receiver_ot(password))
    end_ot = time.perf_counter()
    print("completed OT")
    print(f"Time taken for OT: {end_ot - start_ot:.6f} seconds")

    print("=== Reconstruction ===")
    start_recon = time.perf_counter()
    n = len(shares)
    t = n - 2*8 - 1
    print(f" n: {n}, t: {t}")
    key = reconstruct_secret(shares, t, 8)
    print(f"Reconstructed key: {key}")
    end_recon = time.perf_counter()
    print(f"Time taken for reconstruction: {end_recon - start_recon:.6f} seconds")

    print("=== Explicit Authentication ===")
    start_auth = time.perf_counter()
    shares_prime, pw_prime = decrypt(key, response_data)
    for i, share in enumerate(shares):
        if share not in shares_prime[i]:
            print("file has been tampered with")
            print(f"SESSION KEY: {random_int()}")
            return

    print(f"SESSION KEY: {key}")
    end_auth = time.perf_counter()
    print(f"Time taken for explicit authentication: {end_auth - start_auth:.6f} seconds")

    end = time.perf_counter()

    print(f"Time taken for authentication: {end - start:.6f} seconds")

if __name__ == '__main__':
    while True:
        print("Choose an action:")
        print("1. Register")
        print("2. Authenticate")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            registration()
        elif choice == '2':
            authentication()
        else:
            print("Exiting")
            break