from server  import Server
from client import Client

def run():
    server_pw = '1101010101010101010101010101010101010101010101010101010101010101'
    client_pw = '1101010101010101010101010101010101010101010101010101010101010101'

    server = Server(server_pw)
    client = Client(client_pw)

    shared_key_server, fileblocks, k_prime = server.prepare()
    shared_key_client = client.receive(fileblocks, k_prime)

    print("Shared Keys match:", shared_key_server == shared_key_client)
    print("Server Shared Key:", shared_key_server.hex())
    print("Client Shared Key:", shared_key_client.hex())

if __name__ == '__main__':
    run()