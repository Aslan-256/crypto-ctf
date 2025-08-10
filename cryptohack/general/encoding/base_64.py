import base64

hex_flag = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
byte_flag = bytes.fromhex(hex_flag)
base64_flag = base64.b64encode(byte_flag)
print(base64_flag)  # Output: cyu5t4j8s6q3v7f4n2f7b