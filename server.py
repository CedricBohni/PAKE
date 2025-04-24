import json
import socket
from utils import string_to_bitstring
import os
from ot_protocol import sender_ot
from mpyc.runtime import mpc
from crypto_utils import create_shares, random_int, in_exponent, add_mod

HOST = '127.0.0.1'
PORT = 65433

def registration(username, password):
    bit_password = string_to_bitstring(password)

    print(f"bit_password: {bit_password}")

    n = len(bit_password)
    t = n - 2*8 - 1 # -1 necessary for the reed solomon codes to work
    k = random_int()

    exp_k = in_exponent(k)
    exp_p = in_exponent(int(string_to_bitstring(password), 2))

    session_key_shares = create_shares(k, n, t)

    shares = [None]*n

    for i, bit in enumerate(bit_password):
        if bit == '1':
            shares[i] = (in_exponent(random_int()), in_exponent(session_key_shares[i]))
        else:
            shares[i] = (in_exponent(session_key_shares[i]), in_exponent(random_int()))

    with open(f"{username}_file.json", "w") as f:
        json.dump({"shares": shares, "P": exp_p, "K": exp_k}, f)

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

                                shares = file["shares"]
                                exp_K = file["K"]
                                exp_P = file["P"]
                                # TODO: randomize pw_file

                                k_prime = random_int()
                                exp_K = add_mod(in_exponent(k_prime), exp_K)
                                n = len(shares)
                                t = n - 2 * 8 - 1
                                random_shares = create_shares(k_prime, n, t)
                                for i in range(n):
                                    r = in_exponent(random_shares[i])
                                    shares[i] = (add_mod(shares[i][0], r), add_mod(shares[i][1], r))

                                # TODO: encrypt with new K (new shares and P) -> c
                                # send the c to the client
                                response = "This is a placeholder for the encrypted data"
                                conn.sendall(response.encode())

                                # run OT
                                mpc.run(sender_ot(shares))

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