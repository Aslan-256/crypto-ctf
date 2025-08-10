from Crypto.Util.number import long_to_bytes

xored_hex_flag = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
xored_hex_flag = [xored_hex_flag[i:i+2] for i in range(0, len(xored_hex_flag), 2)]
xored_int_flag = [int(x, 16) for x in xored_hex_flag]
for i in range(256):
    flag = [hex(x ^ i)[2:].zfill(2) for x in xored_int_flag]
    flag = bytes.fromhex(''.join(flag))
    if b"crypto{" in flag:
        print(f"Found favourite byte: {i}")
        print(f"Flag: {flag.decode()}")
        break