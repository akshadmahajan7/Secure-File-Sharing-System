import os
from flask import current_app

def save_encrypted_file(file_data: bytes, filename: str) -> str:
    """
    Saves the encrypted file data to the configured local storage directory.
    Returns the full storage path.
    """
    path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    # Ensure the upload directory exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(file_data)
    return path

def load_encrypted_file(path: str) -> bytes:
    """Loads the encrypted file data from disk."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found at path: {path}")
    with open(path, 'rb') as f:
        return f.read()
