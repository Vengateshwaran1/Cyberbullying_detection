import socket
import ssl
import threading
import random

# Server configuration
HOST = 'localhost'
PORT = 12345
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

clients = []
client_names = {}

# Predefined anonymous names
available_names = ['AnonymousFox', 'MysteriousTiger', 'InvisiblePanda', 'SilentEagle', 'ShadowWolf', 'HiddenLion', 'GhostBear']

# Welcome banner
def show_banner():
    return """
    **********************************
    *  WELCOME TO THE ANONYMOUS CHAT *
    *  Be nice and have fun!         *
    **********************************
    """

def handle_client(client_socket, client_address):
    # Ensure there are available names left
    if available_names:
        # Assign a random anonymous name to the client
        client_name = random.choice(available_names)
        available_names.remove(client_name)  # Remove the assigned name from the list
        client_names[client_socket] = client_name
    else:
        # If no names are left, assign a generic name
        client_name = f"Client{len(clients)+1}"

    print(f"[INFO] Connection from {client_name} ({client_address}) established")
    clients.append(client_socket)

    # Send the banner and welcome message to the client
    client_socket.send(show_banner().encode('utf-8'))
    client_socket.send(f"Welcome, {client_name}! You can start chatting now.\n".encode('utf-8'))

    # Notify other clients about the new user
    broadcast_message(f"[SERVER] {client_name} has joined the chat!", client_socket)

    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"[MESSAGE] {client_name}: {message}")

            # Broadcast the message to all other clients
            broadcast_message(f"{client_name}: {message}", client_socket)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        print(f"[INFO] {client_name} disconnected")
        clients.remove(client_socket)
        del client_names[client_socket]

        # Return the client's name back to the available pool
        if client_name in available_names:
            print(f"[WARNING] Name '{client_name}' was already in the pool!")
        else:
            available_names.append(client_name)

        # Notify others that the client has left
        broadcast_message(f"[SERVER] {client_name} has left the chat.", client_socket)
        
        client_socket.close()

def broadcast_message(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode('utf-8'))
            except Exception as e:
                print(f"[ERROR] {e}")

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"[INFO] Server is running on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
            
            # Start a new thread to handle the client connection
            client_thread = threading.Thread(target=handle_client, args=(ssl_client_socket, client_address))
            client_thread.start()
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
