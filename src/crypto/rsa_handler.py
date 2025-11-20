from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_key_pair():
    """Generates a new RSA public/private key pair (2048 bits)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize private key (PKCS8 format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # WARNING: NoEncryption is used here for simplicity. 
        # In a real application, the private key should be encrypted 
        # using a user-provided passphrase (e.g., PBKDF2HMAC)
        encryption_algorithm=serialization.NoEncryption() 
    ).decode('utf-8')
    
    # Serialize public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem

def wrap_aes_key(aes_key: bytes, recipient_public_key_pem: str) -> bytes:
    """
    Encrypts the symmetric AES key using the recipient's public RSA key (Key Wrapping).
    Uses OAEP padding with SHA256 for optimal security.
    """
    public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8')
    )
    
    wrapped_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key

def unwrap_aes_key(wrapped_key: bytes, private_key_pem: str) -> bytes:
    """
    Decrypts the AES key using the user's private RSA key (Key Unwrapping).
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None # Since NoEncryption was used in generation
    )
    
    aes_key = private_key.decrypt(
        wrapped_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key
