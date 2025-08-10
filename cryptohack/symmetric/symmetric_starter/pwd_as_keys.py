from Crypto.Cipher import AES
import hashlib
import random

# /usr/share/dict/words from
# https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
with open("./words") as f:
    words = [w.strip() for w in f.readlines()]
# keyword = random.choice(words)

# KEY = hashlib.md5(keyword.encode()).digest()
FLAG = "crypto{this_is_a_flag}"


# @chal.route('/passwords_as_keys/decrypt/<ciphertext>/<password_hash>/')
def decrypt(ciphertext, password_hash):
    ciphertext = bytes.fromhex(ciphertext)
    key = bytes.fromhex(password_hash)

    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


# @chal.route('/passwords_as_keys/encrypt_flag/')
def encrypt_flag():
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(FLAG.encode())

    return {"ciphertext": encrypted.hex()}

# {"ciphertext":"c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"}

ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"
for password in words:
    KEY = hashlib.md5(password.encode()).digest()
    try:
        result = decrypt(ciphertext, KEY.hex())
        #convert from hex result['plaintext']
        result['plaintext'] = bytes.fromhex(result['plaintext']).decode('utf-8', errors='ignore')
        if "crypto{" in result['plaintext']:
            print(f"Flag: {result['plaintext']}")
            break
    except Exception as e:
        print(f"Error with password '{password}': {e}")