from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
from datetime import datetime, timedelta

FLAG = "crypto{this_is_a_flag}"
KEY = hashlib.md5(b"secret_key").digest()  # Replace with your actual key

def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}

def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    # print(expires_at)
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    # print(padded[:16], padded[16:32])
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}

if __name__ == "__main__":
    #get_cookie_result = get_cookie()["cookie"]
    get_cookie_result = "39f14bb2adb8d0b1ca5a1f4c403cf7bc176af3907d0e0a182c18d962e488b9e9378dd642a8a493b67bf74efc32d01877" #from the server response
    iv = get_cookie_result[:2*16]
    cookie = get_cookie_result[2*16:]
    #print(cookie[:2*16], cookie[2*16:])
    #I want to xor the first 16 bytes of the cookie with b"admin=True;;expi" xor 0*6+"False"+0*5
    mask = bytes([a ^ b for a, b in zip(b"\x00" * 6 + b"True;;" + b"\x00" * 5, b"\x00" * 6 + b"False" + b"\x00" * 5)])
    #print(mask)
    modified_iv = bytes([a ^ b for a, b in zip(mask, bytes.fromhex(iv))])
    #print(modified_iv.hex())
    #check_admin_result = check_admin(cookie, modified_iv.hex())
    #print(check_admin_result)

    #Actual payload to send to the server
    payload = modified_iv.hex() + cookie
    print(f"Payload to send: {modified_iv.hex()} {cookie}")