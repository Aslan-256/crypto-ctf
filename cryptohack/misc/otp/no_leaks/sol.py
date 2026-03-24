# nc socket.cryptohack.org 13370
# Key insight: c[i] = flag[i] ^ otp[i], and the assertion guarantees c[i] != flag[i].
# So flag[i] is the ONLY value that will never appear at position i across many samples.

from pwn import *
import json
import base64


NUM_SAMPLES = 3000  # coupon collector for 255 values needs ~1500+; use 3000 for safety
FLAG_LEN = 20

r = remote('socket.cryptohack.org', 13370)
r.recvuntil(b'No leaks\n')

seen = [set() for _ in range(FLAG_LEN)]

for i in range(NUM_SAMPLES):
    r.sendline(json.dumps({"msg": "request"}).encode())
    resp = json.loads(r.recvline())
    if 'error' in resp:
        continue
    ct = base64.b64decode(resp['ciphertext'])
    for j, byte in enumerate(ct):
        seen[j].add(byte)

# flag[i] is the byte missing from seen[i]
# The flag consists of printable ASCII, so we can narrow it down
flag = bytearray()
for i in range(FLAG_LEN):
    missing = set(range(256)) - seen[i]
    # Filter to printable ASCII candidates
    candidates = [b for b in missing if 32 <= b < 127]
    if len(candidates) == 1:
        flag.append(candidates[0])
    else:
        # Fallback: pick any missing value (shouldn't happen with enough samples)
        flag.append(missing.pop() if missing else ord('?'))
        print(f"[!] Position {i} has {len(missing)+1} candidates: {missing | set(candidates)}")

print(flag.decode())
r.close()

