from Crypto.Cipher import AES


KEY = b'\x00' * 16  # Replace with your actual key
FLAG = "flag{this_is_a_fake_flag_for_demo_purposes}"  # Replace with your actual flag

def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY) #Vulnerability: using the key as IV
    encrypted = cipher.encrypt(plaintext)

    return {"ciphertext": encrypted.hex()}


def get_flag(key):
    key = bytes.fromhex(key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}

def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode() # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}

if __name__ == "__main__":
    guess = b'\x00' * 16
    result = bytes.fromhex(get_flag(guess.hex())["plaintext"]).decode()
    print(result)
    # I'll decrypt two equal blocks of 16 bytes each one
    # For simplicity I'll picke the encryption of 32 bytes of zeros two times, to be sure to have ascii characters in decryption
    sample_block = encrypt((b"\x00" * 16).hex())["ciphertext"]
    block_to_decrypt = sample_block + sample_block
    result = receive(block_to_decrypt)
    print(result)
    