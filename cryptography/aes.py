# AES encryption and decryption functionality
from Crypto.Cipher import AES
import hashlib
import os

# Generate a 256-bit AES key
def generate_aes_key():
    return os.urandom(32)

# AES-GCM encryption
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return {'ciphertext': ciphertext, 'tag': tag, 'nonce': cipher.nonce}


def aes_decrypt(key, nonce, ciphertext, tag):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except ValueError as e:
        print(f"Decryption error: {e}")
        raise

def derive_aes_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()

# Dynamic usage function
def dynamic_aes_usage():
    # Generate AES key
    aes_key = generate_aes_key()
    print("\nGenerated AES Key (256-bit):")
    print(f"AES Key: {aes_key.hex()}")

    while True:
        choice = input("\nWould you like to encrypt/decrypt a message with AES? (yes/no): ").strip().lower()
        if choice == "yes":
            # Encrypt user input
            message = input("Enter a message to encrypt with AES: ")
            try:
                nonce, ciphertext, tag = aes_encrypt(aes_key, message)
                print(f"\nEncrypted Message (hex): {ciphertext.hex()}")
                print(f"Nonce (hex): {nonce.hex()}")
                print(f"Tag (hex): {tag.hex()}")
                
                # Decrypt the message
                decrypted_message = aes_decrypt(aes_key, nonce, ciphertext, tag)
                print(f"Decrypted Message: {decrypted_message}")
            except Exception as e:
                print(f"Error during encryption/decryption: {str(e)}")
        elif choice == "no":
            print("Exiting the program.")
            break
        else:
            print("Invalid input. Please type 'yes' or 'no'.")
