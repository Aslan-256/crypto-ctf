# The ssh-keygen command is used to produce these public-private keypairs.

# Extract the modulus n as a decimal integer from Bruce's SSH public key.

#file: /bruce_rsa.pub

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Read the SSH public key file
with open("bruce_rsa.pub", "rb") as f:
    key_data = f.read()

# Load the public key
public_key = serialization.load_ssh_public_key(key_data, backend=default_backend())

# Extract the modulus (n)
n = public_key.public_numbers().n

print(n)