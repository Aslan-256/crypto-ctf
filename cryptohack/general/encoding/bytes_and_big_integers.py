from Crypto.Util.number import *

int_flag = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
byte_flag = long_to_bytes(int_flag)
print(byte_flag)  # Output: b'cryptography{Big_integers_are_just_bytes_too}'