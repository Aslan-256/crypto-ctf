label = "label"
ascii_label = [ord(c) for c in label]
flag = ''.join([chr(c^13) for c in ascii_label])  # XOR with 13
print("crypto{"+flag+"}")  # Output: cryptography{XOR_is_a_simple_but_effective_operation}