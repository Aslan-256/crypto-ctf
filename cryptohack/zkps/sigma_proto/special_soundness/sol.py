#!/usr/bin/env python3

# Sigma Protocols - Special Soundness
# Verifier side implementation, exploiting reused randomness to extract the secret

from pwn import * 
import json
import random
from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13426

r = remote(HOST, PORT)


def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

# Parameters

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Receive initial message
print(r.recvline().decode())

# Step 1: Receive first random a and y
res = json_recv()
a = res["a"]
y = res["y"]
msg = res["message"]
print(msg) # "send random e in range 0 <= e < 2^511"

# Step 2: Send first challenge e
e1 = random.randint(0, 2**511 - 1)
request = {
    "e": e1
}
json_send(request)

# Step 3: Receive first response z
res = json_recv()
z1 = res["z"]
msg = res["message"]
print(msg) # "not convinced? I'll happily do it again!"

# Step 4: Receive second random a2 and y
res = json_recv()
a2 = res["a2"]
y2 = res["y"]
msg = res["message"]
print(msg) # "send random e in range 0 <= e < 2^511"

# Step 5: Send second challenge e2
e2 = random.randint(0, 2**511 - 1)
request = {
    "e": e2
}
json_send(request)

# Step 6: Receive second response z2
res = json_recv()
z2 = res["z2"]
msg = res["message"]
print(msg) # "I hope you're convinced I know the flag now. Goodbye :)"

# Step 7: Extract the flag using special soundness

# logic:
# z1 = r + e1*flag mod q
# z2 = r + e2*flag mod q
# I want to recover the secret flag
flag = ((z1 - z2) * pow(e1 - e2, -1, q)) % q
flag_bytes = long_to_bytes(flag)
print(f"Flag: {flag_bytes}")
