from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Constants for GCM (Galois/Counter Mode) components
NONCE_LENGTH = 16 # 128-bit Nonce/IV
TAG_LENGTH = 16   # 128-bit Authentication Tag

def generate_aes_key() -> bytes:
    """Generates a 256-bit (32 byte) random AES key for file encryption."""
    return os.urandom(32)

def encrypt_file_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts file data using AES-256 in GCM mode (Authenticated Encryption).
    The output format is: Nonce (16 bytes) + Tag (16 bytes) + Ciphertext.
    """
    nonce = os.urandom(NONCE_LENGTH)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    
    # Concatenate and return the components
    return nonce + tag + ciphertext

def decrypt_file_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts data encrypted with AES-256 GCM and verifies the authentication tag.
    Raises InvalidTag exception if data is tampered with or key is incorrect.
    """
    if len(encrypted_data) < NONCE_LENGTH + TAG_LENGTH:
        raise ValueError("Encrypted data is truncated or invalid.")
        
    nonce = encrypted_data[:NONCE_LENGTH]
    tag = encrypted_data[NONCE_LENGTH:NONCE_LENGTH + TAG_LENGTH]
    ciphertext = encrypted_data[NONCE_LENGTH + TAG_LENGTH:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decryption verifies the GCM tag automatically. If it fails, an exception is raised.
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
