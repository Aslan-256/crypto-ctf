enc_flag = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"

#test knowing the initial characters of the flag
initial_flag = b"crypto{".hex()
print([chr(int(initial_flag[i:i+2], 16) ^ int(enc_flag[i:i+2], 16)) for i in range(0, len(initial_flag), 2)])
# myXORke from the test

key = b"myXORkey".hex()
print(''.join([chr(int(key[i%16:(i+2)%16 if (i+2)%16 else 16], 16) ^ int(enc_flag[i:i+2], 16)) for i in range(0, len(enc_flag), 2)]))

