from Crypto.Cipher import AES
import requests

BASE_URL = 'https://aes.cryptohack.org/'  # cambia con l'URL corretto del tuo server
BLOCK_SIZE = 16  # Dimensione del blocco AES in byte

def check_padding(hex_ciphertext) -> bool:
    url = f"{BASE_URL}/lazy_cbc/receive/{hex_ciphertext}/"

    response = requests.get(url)

    if response.status_code != 200:
        # print(f"[!] Error in the request: {response.status_code}")
        return False

    data = response.json()

    if 'success' in data:
        # print("[*] ", data['success'])
        return data['success']
    elif 'error' in data:
        # print("[!] ", data['error'])
        return data['error']
    else:
        # print("[!] ", data)
        return data

def encrypt_with_oracle(plaintext: bytes) -> str:
    """
    Sends a request to the oracle to encrypt the plaintext with AES CBC
    """
    hex_plaintext = plaintext.hex()

    url = f"{BASE_URL}/lazy_cbc/encrypt/{hex_plaintext}/"

    response = requests.get(url)

    if response.status_code != 200:
        print(f"[!] Error in the request: {response.status_code}")
        return None

    data = response.json()

    if 'ciphertext' in data:
        return data['ciphertext']
    else:
        print("[!] Error in the response:", data)
        return None
    
def send_key_to_get_flag(key: bytes) -> str:
    """
    Sends a request to get the flag using the provided key
    """
    hex_key = key.hex()
    url = f"{BASE_URL}/lazy_cbc/get_flag/{hex_key}/"

    response = requests.get(url)

    if response.status_code != 200:
        print(f"[!] Error in the request: {response.status_code}")
        return None

    data = response.json()

    if 'plaintext' in data:
        return data['plaintext']
    elif 'error' in data:
        print("[!] ", data['error'])
        return None
    else:
        print("[!] Unexpected response:", data)
        return None

# Esempio di utilizzo
if __name__ == '__main__':
    plaintext = b'0000000000000000'  # 16 bytes of text to encrypt
    ciphertext = encrypt_with_oracle(plaintext)
    if ciphertext:
        print(f"Ciphertext (hex): {ciphertext}")
    decryption_try = check_padding(ciphertext)
    print("Checking good padding, server response:", decryption_try)
    
    decryption_try = check_padding((b'0' * 16).hex()+ciphertext)
    decryption_try = decryption_try[-64:]  # Get the last 64 characters (32 bytes) of the response
    print("Checking bad padding, server response:", decryption_try)
    
    # Vulnerabilities:
    # 1. Using the same key as IV
    # 2. Responding with the hex decrypted plaintext when it is not a valid ASCII

    # Attack:
    # 1. Encrypting P = b'0' * 16, obtaining C = Enc(K, P XOR K) = Enc(K, K)
    # 2. Sending b'0' * 16 concatenated with C to decrypt, it will return an error containing the hex of the decrypted plaintext
    # 3. The second part of this error will contain Dec(K, C) = Dec(K, Enc(K, K)) = K

    key = bytes.fromhex(decryption_try[-32:])
    flag = send_key_to_get_flag(key)
    if flag:
        print(f"Flag (hex): {flag}")
        print(f"Flag (decoded): {bytes.fromhex(flag).decode()}")

    


