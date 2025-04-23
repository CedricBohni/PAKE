import json
import socket
from utils import string_to_bitstring
import os
from ot_protocol import sender_ot
from mpyc.runtime import mpc
from crypto_utils import create_shares, random_share

HOST = '127.0.0.1'
PORT = 65433

def registration(username, password):
    bit_password = string_to_bitstring(password)
    n = len(bit_password)
    session_key = os.urandom(32).hex()

    print(f"Password: {password}")
    print(f"Password in bits: {bit_password}")
    print(f"Session key: {session_key}")

    n = len(bit_password)
    t = n - 2*8
    print(f"Number of shares: {n}")
    print(f"Threshold: {t}")
    # create real shares from the session_key and random_secret
    session_key_shares = create_shares(int(session_key, 16), n, t)
    random_secret_shares = [random_share() for i in range(1, n + 1)]

    array_0 = [None]*n
    array_1 = [None]*n

    for i, bit in enumerate(bit_password):
        if bit == '1':
            array_1[i] = session_key_shares[i]
            array_0[i] = random_secret_shares[i]
        else:
            array_0[i] = session_key_shares[i]
            array_1[i] = random_secret_shares[i]

    with open(f"{username}_file.json", "w") as f:
        json.dump({"session_key": session_key, "array_0": array_0, "array_1": array_1}, f)

    print(f"Shares saved for user {username}")

def set_up():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print("Received:", data.decode())
                    try:
                        message = json.loads(data.decode())
                        action = message.get("action")
                        username = message.get("username")
                        password = message.get("password")

                        if action == "register" and username and password:
                            registration(username, password)
                            response = "Registration successful"
                            conn.sendall(response.encode())
                        elif action == "authenticate" and username:
                            try:
                                with open(f"{username}_file.json", "r") as f:
                                    file = json.load(f)

                                array_0 = file["array_0"]
                                array_1 = file["array_1"]

                                # randomize the shares for every session
                                # create new session key

                                response = "OT ready"
                                conn.sendall(response.encode())

                                mpc.run(sender_ot(array_0, array_1))

                            except FileNotFoundError:
                                response = "User not found"
                                conn.sendall(response.encode())
                        else:
                            response = "Invalid action or data"
                            conn.sendall(response.encode())
                    except json.JSONDecodeError:
                        response = "Invalid JSON format"
                        conn.sendall(response.encode())

if __name__ == "__main__":
    set_up()