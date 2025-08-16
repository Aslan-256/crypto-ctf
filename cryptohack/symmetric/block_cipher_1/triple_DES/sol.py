from Crypto.Cipher import AES
import requests

BASE_URL = 'https://aes.cryptohack.org/'  # cambia con l'URL corretto del tuo server
BLOCK_SIZE = 16  # Dimensione del blocco AES in byte

def encrypt_with_oracle(key: bytes, plaintext: bytes) -> str:
    """
    Sends a request to the oracle to encrypt the plaintext with DES3 ECB
    """
    hex_plaintext = plaintext.hex()
    hex_key = key.hex()

    url = f"{BASE_URL}/triple_des/encrypt/{hex_key}/{hex_plaintext}/"

    response = requests.get(url)

    if response.status_code != 200:
        print(f"[!] Error in the request: {response.status_code}")
        return None

    data = response.json()

    if 'ciphertext' in data:
        return data['ciphertext']
    elif 'error' in data:
        return data['error']
    else:
        print("[!] Error in the response:", data)
        return None
    
def encrypt_flag(key: bytes) -> str:
    """
    Sends a request to encrypt the flag using the provided key
    """
    hex_key = key.hex()
    url = f"{BASE_URL}/triple_des/encrypt_flag/{hex_key}/"

    response = requests.get(url)

    if response.status_code != 200:
        print(f"[!] Error in the request: {response.status_code}")
        return None

    data = response.json()

    if 'ciphertext' in data:
        return data['ciphertext']
    elif 'error' in data:
        return data['error']
    else:
        print("[!] Error in the response:", data)
        return None

if __name__ == '__main__':
    # Vulnerabilities:
    # 1. Using DES
    # 2. Using a key chosen by us
    # 3. WEAK KEY "0000000000000000FFFFFFFFFFFFFFFF" (32 bytes)
    #    Encrypting again an already encrypted ciphertext with this key will be as decrypting it

    # Attack:
    # 1. Ask for the encryption of the flag with the weak key
    # 2. Encrypt the ciphertext with the same key, as it is the same as decrypting it

    weak_key = bytes.fromhex("0000000000000000FFFFFFFFFFFFFFFF")
    encrypted_flag = encrypt_flag(weak_key)
    decrypted_flag = encrypt_with_oracle(weak_key, bytes.fromhex(encrypted_flag))
    if decrypted_flag:
        print(f"Decrypted flag: {bytes.fromhex(decrypted_flag)}")
    else:
        print("Failed to decrypt the flag.") 

    


