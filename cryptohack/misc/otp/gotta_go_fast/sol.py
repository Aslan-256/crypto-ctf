# nc socket.cryptohack.org 13372

from pwn import *
import json
import time
import hashlib
from Crypto.Util.number import long_to_bytes


def generate_key(t: int) -> bytes:
    return hashlib.sha256(long_to_bytes(t)).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


r = remote('socket.cryptohack.org', 13372)
r.recvuntil(b'Gotta go fast!\n')

# Request the encrypted flag and record the time
msg = json.dumps({"option": "get_flag"}) + '\n'
r.send(msg.encode())
t = int(time.time())
resp = json.loads(r.recvline())
enc_flag = bytes.fromhex(resp['encrypted_flag'])

# Try timestamps in a small window around the request time
for dt in range(-3, 4):
    key = generate_key(t + dt)
    candidate = xor_bytes(enc_flag, key)
    if candidate.startswith(b'crypto{'):
        print(candidate.decode())
        break
else:
    print("[-] Failed to recover flag. Try running again.")

r.close()
