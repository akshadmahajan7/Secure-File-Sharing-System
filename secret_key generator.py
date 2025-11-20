import os

# Generate 32 random bytes (which will result in a 64-character hex string)
random_bytes = os.urandom(32)

# Convert the bytes to a hexadecimal string
complex_key = random_bytes.hex()

print(complex_key)
