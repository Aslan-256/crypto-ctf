# archive.cryptohack.org 11840
from pwn import *
import json
from Crypto.Util.number import long_to_bytes
import random

HOST = "archive.cryptohack.org"
PORT = 11840

# Params
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
# w1 = REDACTED
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617

def sigma_simulator():
    z = random.randint(0,q-1)
    e = random.randint(0,2**511-1)
    a = (pow(pow(y1,e,p),-1,p) *pow(g,z,p)) % p
    return a,e,z

def extractor(e0_t1, e1_t1, z0_t1, z1_t1, e0_t2, e1_t2, z0_t2, z1_t2):
    # Determine which side was honestly proved (the one with different e values):
    # This is because the simulated transcript will have a random e value 
    # predetermined indipendent of the s value, 
    # while the honestly proved transcript will have an e value that is 
    # determined by the s value and the other e value so will change when we change s.
    if e0_t1 != e0_t2:
        wb = (z0_t1 - z0_t2) * pow(e0_t1 - e0_t2, -1, q) % q
    else:
        wb = (z1_t1 - z1_t2) * pow(e1_t1 - e1_t2, -1, q) % q
    return wb

def simulator(y0, y1, s):
    e0_sim = random.randint(0, 2**511 - 1)
    e1_sim = s ^ e0_sim
    z0_sim = random.randint(0, q - 1)
    z1_sim = random.randint(0, q - 1)
    a0_sim = (pow(pow(y0, e0_sim, p), -1, p) * pow(g, z0_sim, p)) % p
    a1_sim = (pow(pow(y1, e1_sim, p), -1, p) * pow(g, z1_sim, p)) % p
    return a0_sim, a1_sim, e0_sim, e1_sim, z0_sim, z1_sim

def read_val(prefix):
    r.recvuntil(prefix.encode())
    return int(r.recvline().decode().strip())

def send_val(prefix, val):
    r.recvuntil(prefix.encode())
    r.sendline(str(val).encode())

if __name__ == "__main__":
    r = remote(HOST, PORT)

    # OR proof   

    # Correctness
    r0  = random.randint(0,q-1)
    a0 = pow(g, r0, p)
    send_val("a0:", a0)
    a1, e1, z1 = sigma_simulator()
    send_val("a1:", a1)
    s = read_val("s = ")
    e0 = s ^ e1
    send_val("e0:", e0)
    send_val("e1:", e1)
    z0 = (r0 + e0*w0) % q
    send_val("z0:", z0)
    send_val("z1:", z1)

    # Special soundness
    # transcript 1
    a0_t1 = read_val("a0 = ")
    a1_t1 = read_val("a1 = ")
    s_t1  = read_val("s = ")
    e0_t1 = read_val("e0 = ")
    e1_t1 = read_val("e1 = ")
    z0_t1 = read_val("z0 = ")
    z1_t1 = read_val("z1 = ")
    # transcript 2
    a0_t2 = read_val("a0 = ")
    a1_t2 = read_val("a1 = ")
    s_t2  = read_val("s* = ")
    e0_t2 = read_val("e0* = ")
    e1_t2 = read_val("e1* = ")
    z0_t2 = read_val("z0* = ")
    z1_t2 = read_val("z1* = ")
    # witness extraction
    wb = extractor(e0_t1, e1_t1, z0_t1, z1_t1, e0_t2, e1_t2, z0_t2, z1_t2)
    send_val("witness!", wb)

    # SHVZK 
    y0_s = read_val("y0 = ")
    y1_s = read_val("y1 = ")
    s_shvzk = read_val("s = ")
    a0_sim, a1_sim, e0_sim, e1_sim, z0_sim, z1_sim = simulator(y0_s, y1_s, s_shvzk)
    send_val("a0:", a0_sim)
    send_val("a1:", a1_sim)
    send_val("e0:", e0_sim)
    send_val("e1:", e1_sim)
    send_val("z0:", z0_sim)
    send_val("z1:", z1_sim)

    print(r.recvall().decode().strip())