from Crypto.Cipher import AES
import requests

BASE_URL = 'https://aes.cryptohack.org/'  # cambia con l'URL corretto del tuo server
BLOCK_SIZE = 16  # Dimensione del blocco AES in byte

def encrypt_with_oracle(plaintext: bytes, iv: bytes) -> str:
    """
    Sends a request to the oracle to encrypt the plaintext with DES3 ECB
    """
    hex_plaintext = plaintext.hex()
    hex_iv = iv.hex()

    url = f"{BASE_URL}/symmetry/encrypt/{hex_plaintext}/{hex_iv}/"

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
    
def encrypt_flag() -> str:
    """
    Sends a request to encrypt the flag using the provided key
    """
    url = f"{BASE_URL}/symmetry/encrypt_flag/"

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
    # 1. Using OFB: encrypting a second time with the same key and iv is the same as decrypting
    # 2. Using an iv chosen by us and leaking it in flag encryption

    # Attack:
    # 1. Ask for the encryption of the flag and save the iv
    # 2. Encrypt the obtained ciphertext with the same iv, as it is the same as decrypting it

    encrypted_flag = encrypt_flag()
    if encrypted_flag:
        iv = bytes.fromhex(encrypted_flag[:32])
        ciphertext = bytes.fromhex(encrypted_flag[32:])
        decrypted_flag = bytes.fromhex(encrypt_with_oracle(ciphertext, iv))
        if decrypted_flag:
            print(f"Decrypted flag: {decrypted_flag}")
        else:
            print("Failed to decrypt the flag.")
    else:
        print("Failed to encrypt the flag.")
    
