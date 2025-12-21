from pwn import *
import json
import random

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

r = remote('socket.cryptohack.org', 13427) #socket.cryptohack.org 13427

r.recvline()
data = r.recvline()
e = int(json.loads(data)['e'])
y = int(json.loads(data)['y'])
print(f"e: {e}")
print(f"y: {y}")

# Generate a random z
z = random.randint(0, 2**511)

# Build a valid commitment a s.t. g^z = a * y^e mod p
a = (pow(g, z, p) * pow(pow(y, e, p), -1, p)) % p

# Build the transcript
transcript = {"a": a, "z": z}

r.sendline(json.dumps(transcript).encode())

r.interactive()