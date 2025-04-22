import json
import socket

HOST = '127.0.0.1'
PORT = 65432
def generate_session_key(username):
    # This is a placeholder for session key generation logic
    # In a real-world application, you would use a secure method to generate a session key
    return f"session_key_for_{username}"

def save_registration(username, password):
    # create a sessionKey for the user
    sessionKey = generate_session_key(username)
    # using shamri secret sharing to split the sessionkey into n(password as bits) many shares and save them as a json file


def registration():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT} for registration")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print("Received:", data.decode())
                try:
                    registration_data = json.loads(data.decode())
                    username = registration_data.get("username")
                    password = registration_data.get("password")
                    if username and password:
                        save_registration(username, password)
                        response = "Registration successful"
                    else:
                        response = "Invalid data"
                except json.JSONDecodeError:
                    response = "Invalid JSON format"
                conn.sendall(data)

def password_authentication():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT} for password authentication")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print("Received:", data.decode())
                try:
                    auth_data = json.loads(data.decode())
                    username = auth_data.get("username")
                    password = auth_data.get("password")
                    with open(f"{username}_password.txt", "r") as f:
                        stored_password = f.read()
                    if password == stored_password:
                        response = "Authentication successful"
                    else:
                        response = "Authentication failed"
                except json.JSONDecodeError:
                    response = "Invalid JSON format"
                conn.sendall(response.encode())

if __name__ == "__main__":
    registration()
    print("registration complete")
    password_authentication()
