from pwn import *
import json
from math import log
import os
from hashlib import sha256

FLAG_LEN = 39*2

def conn():
    if args.REMOTE:
        return remote('socket.cryptohack.org', 13402)
    else:
        return remote('localhost', 13402)

def _xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

print(os.urandom(39).hex())

# r = conn()
# r.recvuntil(b"unmix this?\n")
# payload = {
#     "option": "mix",
#     "data": "00"*32
# }
# r.sendline(json.dumps(payload).encode())
# resp = json.loads(r.recvline())
# print(resp)

# ==================================================================================
# idea:
# - compute sha256(0)
# - then mixed_and will be 0 and very_mixed will be the same byte repeated 32 times
# - we can understand the value from data^FLAG if the hashed value differs from our 
#   precomputed hashes
# ==================================================================================

precomputed_hashes = {}
for i in range(256):
    precomputed_hashes[i] = sha256(bytes([i]*39)).hexdigest()

for i in range(256):
    print(f"precomputed hash for {hex(i)}: {precomputed_hashes[i]}")

r = conn()
r.recvuntil(b"unmix this?\n")
data = "00"*39

# ==================================================================================
# test
# ==================================================================================
for i in range (100):
    payload = {
        "option": "mix",
        "data": data
    }
    r.sendline(json.dumps(payload).encode())
    resp = json.loads(r.recvline())
    print(resp)
    if resp["mixed"] in precomputed_hashes.values():
        continue
    else:
        # print(f"server hash: {resp['mixed']}")
        # print(f"index: {i}")    
        # print("Something went wrong")
        exit(1)
# ==================================================================================

bit_test = [1, 2, 4, 8, 16, 32, 64, 128]
flag_bytes = []
for i in range(39):
    flag_byte_bits = []
    for bit in bit_test:
        data = [0]*(i) + [bit] + [0]*(39-i-1)
        payload = {
            "option": "mix",
            "data": bytes(data).hex()
        }
        r.sendline(json.dumps(payload).encode())
        resp = json.loads(r.recvline())
        print(f"test for bit {bit}: {resp}")
        if resp["mixed"] in precomputed_hashes.values():
            flag_byte_bits.append(0)
        else:
            flag_byte_bits.append(1)
    print(flag_byte_bits)
    flag_byte = 0
    for i, bit in enumerate(bit_test):
        if flag_byte_bits[i] == 1:
            flag_byte |= bit
    print(f"flag byte: {hex(flag_byte)}")
    print(f"flag byte char: {chr(flag_byte)}")
    flag_bytes.append(flag_byte)
print("FLAG: " + "".join([chr(b) for b in flag_bytes]))

