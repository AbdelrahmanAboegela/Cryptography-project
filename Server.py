import socket
import threading

HOST = '127.0.0.1'  
PORT = 9999         

clients = []  

def handle_client_connection(client_socket):
    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break
            broadcast(data, client_socket)
    except ConnectionResetError:
        clients.remove(client_socket)
        client_socket.close()

def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode('utf-8'))
            except ConnectionResetError:
                # Handle client disconnect
                clients.remove(client)
                client.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server listening on {HOST}:{PORT}...")

    while True:
        client_socket, _ = server.accept()
        clients.append(client_socket)

        thread = threading.Thread(target=handle_client_connection, args=(client_socket,))
        thread.start()

if __name__ == "__main__":
    start_server()
