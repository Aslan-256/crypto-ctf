import random
from collections import namedtuple
import gmpy2
from Crypto.Util.number import isPrime, bytes_to_long, inverse, long_to_bytes

FLAG = b'crypto{??????????????????????????}'
PrivateKey = namedtuple("PrivateKey", ['b', 'r', 'q'])

def gen_private_key(size): # if flag_size = 34, then size = 34*8 = 272
    s = 10000
    b = []
    for _ in range(size):
        ai = random.randint(s + 1, 2 * s)
        assert ai > sum(b)
        b.append(ai)
        s += ai
    # at this point s = 10000 + sum(b) and b is composed of exponentially growing numbers ai
    while True:
        q = random.randint(2 * s, 32 * s) # very large prime
        if isPrime(q):
            break
    r = random.randint(s, q)
    assert q > sum(b)
    assert gmpy2.gcd(q,r) == 1
    return PrivateKey(b, r, q)


def gen_public_key(private_key: PrivateKey):
    a = []
    for x in private_key.b:
        a.append((private_key.r * x) % private_key.q) # a[i] = (r * b[i]) % q = r * b[i] + k * q
    return a


def encrypt(msg, public_key):
    assert len(msg) * 8 <= len(public_key)
    ct = 0
    msg = bytes_to_long(msg)
    for bi in public_key:
        ct += (msg & 1) * bi
        msg >>= 1
    return ct   # sum of a[i] values where the i-th bit of msg is 1, so 
                # ct = a[x0] + ... + a[xj]  = r * (b[x0] + ... + b[xj]) + k * j * q where msg[xi] = 1


def decrypt(ct, private_key: PrivateKey):
    ct = inverse(private_key.r, private_key.q) * ct % private_key.q # ct' = r_inv * ct % q = r_inv * ct + k' * q
    msg = 0
    for i in range(len(private_key.b) - 1, -1, -1):
        if ct >= private_key.b[i]:
            msg |= 1 << i
            ct -= private_key.b[i]
    return long_to_bytes(msg)


private_key = gen_private_key(len(FLAG) * 8)
public_key = gen_public_key(private_key)
encrypted = encrypt(FLAG, public_key)
decrypted = decrypt(encrypted, private_key)
assert decrypted == FLAG

print(f'Public key: {public_key}')
print(f'Encrypted Flag: {encrypted}')
