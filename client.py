import json
import socket
from utils import string_to_bitstring
from ot_protocol import receiver_ot
from mpyc.runtime import mpc

HOST = '127.0.0.1'
PORT = 65433

# Client that sends the registration data to the server in a json format
def send_registration():
    print("=== User Registration ===")
    username = input("Enter username: ")
    password = input("Enter password: ")

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

def send_authentication():
    print("=== User Authentication ===")
    username = input("Enter username: ")
    password = [int(bit) for bit in string_to_bitstring(input("Enter password: "))]

    auth_data = {
        "action": "authenticate",
        "username": username,
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        payload = json.dumps(auth_data)
        s.sendall(payload.encode())
        response = s.recv(1024).decode()
        print(f"\nServer response: {response}")

    mpc.run(receiver_ot(password))

    # reconstrcut session_key with shares

    session_key = 0
    print (f"Session key: {session_key}")

if __name__ == '__main__':
    while True:
        print("Choose an action:")
        print("1. Register")
        print("2. Authenticate")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            send_registration()
        elif choice == '2':
            send_authentication()
        else:
            print("Exiting")
            break