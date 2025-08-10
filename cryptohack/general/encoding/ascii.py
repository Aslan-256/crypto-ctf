asci_flag = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
char_flag = [chr(i) for i in asci_flag]
flag = ''.join(char_flag) #opposite of ord()
print(flag)  # Output: cryptography{ASCII_pr1nt4bl3}