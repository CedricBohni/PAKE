import json
import socket

HOST = '127.0.0.1'
PORT = 65432

# Client that sends the registration data to the server in a json format
def send_registration():
    print("=== User Registration ===")
    username = input("Enter username: ")
    password = input("Enter password: ")

    registration_data = {
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
    password = input("Enter password: ")

    auth_data = {
        "username": username,
        "password": password
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        payload = json.dumps(auth_data)
        s.sendall(payload.encode())
        response = s.recv(1024).decode()
        print(f"\nServer response: {response}")

if __name__ == '__main__':
    send_registration()
    print("registration complete")
    send_authentication()