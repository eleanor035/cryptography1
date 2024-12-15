from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import os

# Directory to store keys and certificates
STORAGE_DIR = "security_storage"
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# Utility functions for storing and retrieving keys
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

# ECC Key generation (P-256 curve)
def generate_ecc_keys():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    
    # Export keys in PEM format
    private_key_bytes = private_key.export_key(format='PEM')
    public_key_bytes = public_key.export_key(format='PEM')
    
    return private_key_bytes, public_key_bytes

# ECC Signing (using DSS and SHA256)
def ecc_sign(private_key_bytes, data):
    private_key = ECC.import_key(private_key_bytes)
    signer = DSS.new(private_key, 'fips-186-3')
    h = SHA256.new(data.encode())
    signature = signer.sign(h)
    return signature

# ECC Verification
def ecc_verify(public_key_bytes, data, signature):
    public_key = ECC.import_key(public_key_bytes)
    verifier = DSS.new(public_key, 'fips-186-3')
    h = SHA256.new(data.encode())
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# Generate and store ECC keys for Controller (simulating)
def setup_controller_ecc_keys():
    controller_private, controller_public = generate_ecc_keys()
    store_file("controller_ecc_private.pem", controller_private)
    store_file("controller_ecc_public.pem", controller_public)

# Generate and store ECC keys for Agent1 (simulating)
def setup_agent1_ecc_keys():
    agent1_private, agent1_public = generate_ecc_keys()
    store_file("agent1_ecc_private.pem", agent1_private)
    store_file("agent1_ecc_public.pem", agent1_public)
