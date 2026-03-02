# socket.cryptohack.org 13429
from pwn import *
from Crypto.Util.number import long_to_bytes
import json

# Connestion params
HOST = "socket.cryptohack.org"
PORT = 13429

# Girault's params
g = 2
k1 = 512
k2 = 128
S = 2**k1
R = 2**(2*k2+k1)

if __name__ == "__main__":
    r = remote(HOST, PORT)

    # Receive the initial message from the server
    r.recvline()
    data = json.loads(r.recvline().decode())
    y = data["y"]
    a = data["a"]

    # Send a random challenge e in range 0 <= e < 2^{k2}
    # FLAW: as malicious verifier, we can choose e to be R, which is larger than 2^{k2}
    # so that the prover will compute z = r + e*flag and 
    # we will be able to recover the flag by computing z//e, since r < R.
    e = R 
    r.sendline(json.dumps({"e": e}).encode())

    # Receive the response from the server
    data = json.loads(r.recvline().decode())
    z = data["z"]

    # Compute the flag using the response
    flag = z//e
    print(long_to_bytes(flag).split(b'}')[0]+b'}')

    