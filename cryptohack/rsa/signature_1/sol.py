from pwn import *
import json
from pkcs1 import emsa_pkcs1_v15
from Crypto.Util.number import bytes_to_long

r = remote('socket.cryptohack.org', 13391)

r.recvuntil(b'domain.\n')
r.sendline(json.dumps({
    "option": "get_signature"
}).encode())
res = json.loads(r.recvline())
N = int(res['N'], 16)
e = int(res['e'], 16)
signature = int(res['signature'], 16)
print(f"N: {N}\ne: {e}\nsignature: {signature}")
msg = "I am Mallory. own CryptoHack.org"
digest = bytes_to_long(emsa_pkcs1_v15.encode(msg.encode(), 256))
e = 1
tmp = pow(signature, e)
N = tmp - digest # tmp = N + digest
# print the bytes number of N and msg
print(f"N bytes: {N.bit_length() // 8}\nmsg bytes: {len(msg)}")


r.sendline(json.dumps({
    "option": "verify",
    "msg": msg,
    "N": hex(N),
    "e": hex(e)
}).encode())

print(r.recvline())

r.interactive()