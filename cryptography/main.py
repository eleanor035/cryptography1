import threading
from entities import run_node
from rsa import generate_rsa_keys, encrypt_rsa_message, decrypt_rsa_message
from ecc import generate_ecc_keys, ecc_sign, ecc_verify
from aes import generate_aes_key, aes_encrypt, aes_decrypt, derive_aes_key

# Create a lock for thread-safe printing
print_lock = threading.Lock()

# Flag to ensure the server message is printed only once
server_message_printed = False

# Function to start the peer node
def start_p2p_node(my_port, known_peers):
    global server_message_printed
    if not server_message_printed:
        with print_lock:
            print(f"[INFO] Node is listening on port {my_port}...")  # Print only once
        server_message_printed = True  # Set the flag to True after printing
    run_node(my_port, known_peers)  # Start the node

# Function to send a message to a peer (generalized for all cryptographic types)
def send_message_to_peer(peer_address, message, message_type='text'):
    if message_type == 'rsa':
        send_rsa_message(peer_address, message)
    elif message_type == 'aes':
        send_aes_message(peer_address, message)
    elif message_type == 'ecc':
        send_ecc_message(peer_address, message)
    else:
        print(f"Sending plain message to {peer_address}: {message}")

# RSA example: encrypt and send a message
def send_rsa_message(peer_address, message):
    encrypted_message = encrypt_rsa_message(public_key, message)
    print(f"\nEncrypted RSA Message: {encrypted_message}")
    send_message_to_peer(peer_address, encrypted_message, message_type='rsa')

# AES example: encrypt and send a message
def send_aes_message(peer_address, message):
    encrypted_message = aes_encrypt(aes_key, message)
    print(f"\nEncrypted AES Message: {encrypted_message['ciphertext'].hex()}")
    send_message_to_peer(peer_address, encrypted_message, message_type='aes')

# ECC example: sign and send a message
def send_ecc_message(peer_address, message):
    signature = ecc_sign(private_key_ecc, message)
    print(f"\nECC Signature: {signature}")
    send_message_to_peer(peer_address, signature, message_type='ecc')

# Function to handle the reception of messages based on encryption type
def handle_received_message(peer_address, encrypted_message, message_type='text'):
    if message_type == 'rsa':
        handle_rsa_message(peer_address, encrypted_message)
    elif message_type == 'aes':
        handle_aes_message(peer_address, encrypted_message)
    elif message_type == 'ecc':
        handle_ecc_message(peer_address, encrypted_message)
    else:
        print(f"Received plain message from {peer_address}: {encrypted_message}")

# RSA message decryption
def handle_rsa_message(peer_address, encrypted_message):
    decrypted_message = decrypt_rsa_message(private_key, encrypted_message)
    print(f"\nDecrypted RSA Message from {peer_address}: {decrypted_message}")

# AES message decryption
def handle_aes_message(peer_address, encrypted_message):
    decrypted_message = aes_decrypt(aes_key, encrypted_message['nonce'], encrypted_message['ciphertext'], encrypted_message['tag'])
    print(f"\nDecrypted AES Message from {peer_address}: {decrypted_message}")

# ECC message verification
def handle_ecc_message(peer_address, signature):
    is_valid = ecc_verify(public_key_ecc, message, signature)
    print(f"\nECC Signature valid from {peer_address}: {is_valid}")

# Main interactive menu
if __name__ == "__main__":
    print("=== P2P Node with Cryptographic Functions ===")
    
    # Get P2P node configuration
    my_port = int(input("Enter port for this node: "))
    known_peer_count = int(input("Enter number of known peers: "))
    known_peers = []

    for _ in range(known_peer_count):
        ip = input("Enter peer IP: ")
        port = int(input("Enter peer port: "))
        known_peers.append((ip, port))

    # Start the P2P node in a thread
    node_thread = threading.Thread(target=start_p2p_node, args=(my_port, known_peers))
    node_thread.daemon = True
    node_thread.start()

    # Example RSA key pair
    private_key, public_key = generate_rsa_keys()
    
    # Example AES key
    password = "example_password"
    aes_key = derive_aes_key(password)

    # Example ECC keys
    private_key_ecc, public_key_ecc = generate_ecc_keys()

    # Main menu options
    print("\nOptions:")
    print("1. Send Message to a Peer")
    print("2. Broadcast Message")
    print("3. Add Peer")
    print("4. Show Peers")
    print("5. Exit")
        
    while True:    
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            # Ask for the peer details and then show the message sending options
            peer_ip = input("Enter peer IP: ")
            peer_port = int(input("Enter peer port: "))

            while True:
                print("\nMessage Sending Options:")
                print("1. Send RSA Encrypted Message")
                print("2. Send ECC Signed Message")
                print("3. Send AES Encrypted Message")
                print("4. Go back to the main menu")

                msg_choice = input("Enter your choice: ").strip()

                if msg_choice == "1":
                    message = input("Enter message to send (RSA): ")
                    send_rsa_message((peer_ip, peer_port), message)
                elif msg_choice == "2":
                    message = input("Enter message to send (ECC): ")
                    send_ecc_message((peer_ip, peer_port), message)
                elif msg_choice == "3":
                    message = input("Enter message to send (AES): ")
                    send_aes_message((peer_ip, peer_port), message)
                elif msg_choice == "4":
                    break  # Go back to the main menu
                else:
                    print("Invalid choice, please try again.")

        elif choice == "2":
            # Broadcast message (this functionality can be added later)
            print("Broadcast message functionality is not implemented yet.")
        
        elif choice == "3":
            # Add peer manually
            ip = input("Enter peer IP: ")
            port = int(input("Enter peer port: "))
            known_peers.append((ip, port))  # Add the peer to the list
            print(f"[Info] Added peer: {ip}:{port}")
        
        elif choice == "4":
            # Show peers (this could display the list of connected peers)
            print("Peers:", known_peers)
        
        elif choice == "5":
            print("Exiting program...")
            break

        else:
            print("Invalid choice. Please try again.")
