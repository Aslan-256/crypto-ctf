from pwn import *
import json

def conn():
    if args.REMOTE:
        return remote('socket.cryptohack.org', 13395)
    else:
        return remote('localhost', 13395)
    
r = conn()
r.recvuntil(b'dates."\n')
a = "00"*4
b = "01"*4 # useless for out analysis
payload = json.dumps({"a": a, "b": b}).encode()
r.sendline(payload)
print(r.recvline())

# ============================================================
# from chall.py modified interaction
# ============================================================
# python3 chall.py 
# Iteration 0:
# After XOR with block: [16, 32, 48, 80, 80, 96, 112, 128]
# matrix bit form:
# 00010000
# 00100000
# 00110000
# 01010000
# 01010000
# 01100000
# 01110000
# 10000000
# After permutation: [0, 0, 0, 0, 93, 102, 120, 128]
# matrix bit form:
# 00000000
# 00000000
# 00000000
# 00000000
# 01011101
# 01100110
# 01111000
# 10000000
# we have won: idx=7, x=128, s=155, x_new=80
# bit form: x=10000000, x_new=01010000
# After substitution: [240, 240, 240, 240, 1, 128, 125, 155]
# ============================================================
# we need to change a 128 to 80 bitflipping the right bits
# 128 = 10000000
#  80 = 01010000
# we need to flip the last 4 bits.
# However these numbers are in the after-permutation state
# so we need to flip the most significant bits of 3 of the 
# last 4 states (those that depends on our input block):
# state[7, 6 and 4] -> input[3, 2 and 0]
# note: from 0 we will obtain 128 (0x80) by flipping the msb
# ------------------------------------------------------------
a = "00"*4
b_0 = "80"
b_1 = "00"
b_2 = "80"
b_3 = "80"
b = b_0 + b_1 + b_2 + b_3
payload = json.dumps({"a": a, "b": b}).encode()
r.sendline(payload)
print(r.recvline())