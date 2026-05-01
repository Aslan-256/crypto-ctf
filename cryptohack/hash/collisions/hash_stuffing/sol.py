from pwn import *
import json

# 2^128 collision protection!
BLOCK_SIZE = 32

# Nothing up my sleeve numbers (ref: Dual_EC_DRBG P-256 coordinates)
W = [0x6b17d1f2, 0xe12c4247, 0xf8bce6e5, 0x63a440f2, 0x77037d81, 0x2deb33a0, 0xf4a13945, 0xd898c296]
X = [0x4fe342e2, 0xfe1a7f9b, 0x8ee7eb4a, 0x7c0f9e16, 0x2bce3357, 0x6b315ece, 0xcbb64068, 0x37bf51f5]
Y = [0xc97445f4, 0x5cdef9f0, 0xd3e05e1e, 0x585fc297, 0x235b82b5, 0xbe8ff3ef, 0xca67c598, 0x52018192]
Z = [0xb28ef557, 0xba31dfcb, 0xdd21ac46, 0xe2a91e3c, 0x304f44cb, 0x87058ada, 0x2cb81515, 0x1e610046]

# Lets work with bytes instead!
W_bytes = b''.join([x.to_bytes(4,'big') for x in W])
X_bytes = b''.join([x.to_bytes(4,'big') for x in X])
Y_bytes = b''.join([x.to_bytes(4,'big') for x in Y])
Z_bytes = b''.join([x.to_bytes(4,'big') for x in Z])

def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)

def blocks(data):
    return [data[i:(i+BLOCK_SIZE)] for i in range(0,len(data),BLOCK_SIZE)]

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

def rotate_left(data, x):
    x = x % BLOCK_SIZE
    return data[x:] + data[:x]

def rotate_right(data, x):
    x = x % BLOCK_SIZE
    return  data[-x:] + data[:-x]

def scramble_block(block):
    for _ in range(40): # 40 = 32 + 8 so first 8 are xored back in the end
        block = xor(W_bytes, block)
        block = rotate_left(block, 6)
        block = xor(X_bytes, block)
        block = rotate_right(block, 17)
    return block

def cryptohash(msg):
    initial_state = xor(Y_bytes, Z_bytes)
    msg_padded = pad(msg)
    msg_blocks = blocks(msg_padded)
    for i,b in enumerate(msg_blocks):
        mix_in = scramble_block(b)
        for _ in range(i): # repeated 64 times will cancel itself out
            mix_in = rotate_right(mix_in, i+11)
            mix_in = xor(mix_in, X_bytes)
            mix_in = rotate_left(mix_in, i+6)
        # print(f"mix_in after block {i}: {mix_in.hex()}")
        initial_state = xor(initial_state,mix_in)
    return initial_state.hex()

def inverse_scramble_block(block):
    for _ in range(40):
        block = rotate_left(block, 17)
        block = xor(X_bytes, block)
        block = rotate_right(block, 6)
        block = xor(W_bytes, block)
    return block

def inverse_mix_in_single_block(mix_in): # useless: for a single block there is no mixing
    # mix_in = rotate_right(mix_in, 6)
    # mix_in = xor(mix_in, X_bytes)
    # mix_in = rotate_left(mix_in, 11)
    return mix_in
    


msg_1 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
hash_val_1 = cryptohash(msg_1)
print(hash_val_1)
wanted = hash_val_1

# ==========================================================================
# visual scheme
# ==========================================================================
# B_0 -> [scarmbling&mixing] -> tmp_0 -(XOR)-> H_1
#                                        ^
#                                        |
# H_0 = Y XOR Z -------------------------
# ===========================================================================
# B_1 -> [scarmbling&mixing] -> tmp_1 -(XOR)-> H_2
#                                        ^
#                                        |
# H_1 ------------------------------------------
# ===========================================================================
# we want a single-block message that produces H_2, so 
#   - put H_1' = H_2
#   - invert xoring with H_0 obtaining a wanted tmp_0'
#   - invert scrambling&mixing to obtain a wanted B_0'
# ============================================================================

wanted_single_block = bytes.fromhex(wanted)
print(f"wanted_single_block: {wanted_single_block.hex()}")
wanted_tmp_0 = xor(bytes.fromhex(wanted), xor(Y_bytes, Z_bytes))
print(f"wanted_tmp_0: {wanted_tmp_0.hex()}")
wanted_B_0 = inverse_scramble_block(wanted_tmp_0)
print(f"wanted_B_0: {wanted_B_0.hex()}")

print(f"Hash of wanted_B_0: {cryptohash(wanted_B_0)}")
print(f"Hash of msg_1: {hash_val_1}")

msg_2 = wanted_B_0

r = remote('socket.cryptohack.org', 13405)

r.recvuntil(b'JSON: ')
payload = json.dumps({"m1": msg_1.hex(), "m2": msg_2.hex()})
r.sendline(payload.encode())
res = json.loads(r.recvline().decode())
print(res)

