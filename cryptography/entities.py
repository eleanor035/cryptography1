import socket
import threading
import os

# Constants
STORAGE_DIR = "security_storage"
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# Node Configuration
PEER_PORT = None  # Port for the current node
PEERS = []  # List of known peers (IP, Port)

# Store keys or certificates
def store_file(filename, data):
    filepath = os.path.join(STORAGE_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(data)

def read_file(filename):
    filepath = os.path.join(STORAGE_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            return f.read()
    return None

# Server Functionality: Listen for connections
def start_server(port):
    global PEER_PORT
    PEER_PORT = port

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', port))
    server.listen(5)
    print(f"[Server] Node is listening on port {port}...")

    while True:
        conn, addr = server.accept()
        print(f"[Server] Connection received from {addr}")
        handle_connection(conn)

def handle_connection(conn):
    try:
        message = conn.recv(1024).decode()
        print(f"[Server] Message received: {message}")
        # Respond to messages
        response = f"Message '{message}' received successfully!"
        conn.send(response.encode())
    except Exception as e:
        print(f"[Server] Error handling connection: {e}")
    finally:
        conn.close()

# Client Functionality: Connect to peers
def send_message_to_peer(peer_address, message):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(peer_address)
        client.sendall(message.encode())

        # Receive response
        response = client.recv(1024).decode()
        print(f"[Client] Response from {peer_address}: {response}")
        client.close()
    except Exception as e:
        print(f"[Client] Failed to connect to peer {peer_address}: {e}")

# Function to broadcast a message to all peers
def broadcast_message(message):
    print(f"[Client] Broadcasting message: {message}")
    for peer in PEERS:
        send_message_to_peer(peer, message)

# Add a peer to the known list
def add_peer(ip, port):
    if (ip, port) not in PEERS:
        PEERS.append((ip, port))
        print(f"[Info] Added peer: {ip}:{port}")
    else:
        print(f"[Info] Peer already known: {ip}:{port}")

# Main function for each entity
def run_node(port, known_peers=[]):
    # Add known peers
    for peer in known_peers:
        add_peer(*peer)

    # Start the server in a thread
    server_thread = threading.Thread(target=start_server, args=(port,))
    server_thread.daemon = True
    server_thread.start()

    # Simulate sending messages to peers
    while True:
        print("\nOptions: \n1. Send Message to a Peer \n2. Broadcast Message \n3. Add Peer \n4. Show Peers \n5. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            ip = input("Enter peer IP: ")
            peer_port = int(input("Enter peer port: "))
            message = input("Enter message to send: ")
            send_message_to_peer((ip, peer_port), message)
        elif choice == "2":
            message = input("Enter message to broadcast: ")
            broadcast_message(message)
        elif choice == "3":
            ip = input("Enter peer IP: ")
            peer_port = int(input("Enter peer port: "))
            add_peer(ip, peer_port)
        elif choice == "4":
            print(f"Known peers: {PEERS}")
            for peer in PEERS:
                print(f"IP: {peer[0]}, Port: {peer[1]}")
        elif choice == "5":
            print("Exiting node...")
            break
        else:
            print("Invalid choice. Try again.")

# Run nodes (examples)
if __name__ == "__main__":
    print("Starting P2P Node...")
    my_port = int(input("Enter port for this node: "))
    known_peer_count = int(input("Enter number of known peers: "))
    known_peers = []

    for _ in range(known_peer_count):
        ip = input("Enter peer IP: ")
        port = int(input("Enter peer port: "))
        known_peers.append((ip, port))

    run_node(my_port, known_peers)