from pwn import *
import json

r = remote("socket.cryptohack.org", 13380)

r.recvuntil(b"Alice: ")
alice_data = json.loads(r.recvline())
p = int(alice_data['p'], 16)
g = int(alice_data['g'], 16)
A = int(alice_data['A'], 16)

r.recvuntil(b"Bob: ")
bob_data = json.loads(r.recvline())
B = int(bob_data['B'], 16)

r.recvuntil(b"Alice: ")
alice_data = json.loads(r.recvline())
iv = alice_data['iv']
ciphertext = alice_data['encrypted']

print(f"p: {p}")
print(f"g: {g}")
print(f"A: {A}")
print(f"B: {B}")
print(f"iv: {iv}")
print(f"ciphertext: {ciphertext}")

r.close()

# We are in an additive group, so
# - A = g*a mod p
# - B = g*b mod p
g_inverse = pow(g, -1, p)
b = (B * g_inverse) % p
shared_secret = b*A % p

print(f"g^-1: {g_inverse}")
print(f"b: {b}")
print(f"shared_secret: {shared_secret}")

# ===================================================
# from deriving_symmetric_key/decrypt.py
# ===================================================
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')
# ===================================================

print(decrypt_flag(shared_secret, iv, ciphertext))