import requests

# URL BASE del server che espone l'oracolo ECB
BASE_URL = 'https://aes.cryptohack.org/'  # cambia con l'URL corretto del tuo server
BLOCK_SIZE = 16  # Dimensione del blocco AES in byte

def encrypt_with_oracle(plaintext: bytes) -> str:
    """
    Invia una richiesta all'oracolo per cifrare il plaintext con AES ECB
    """
    # Codifica il plaintext in esadecimale (richiesto dall'endpoint)
    hex_plaintext = plaintext.hex()

    # Costruisce l'URL completo
    url = f"{BASE_URL}/ecb_oracle/encrypt/{hex_plaintext}/"

    # Invia la richiesta GET
    response = requests.get(url)

    if response.status_code != 200:
        print(f"[!] Errore nella richiesta: {response.status_code}")
        return None

    data = response.json()

    if 'ciphertext' in data:
        return data['ciphertext']
    else:
        print("[!] Errore nella risposta:", data)
        return None

# Esempio di utilizzo
if __name__ == '__main__':
    plaintext = b'TestInput123'  # testo che vuoi cifrare
    ciphertext = encrypt_with_oracle(plaintext)
    if ciphertext:
        print(f"Ciphertext (hex): {ciphertext}")

    SECRET_LEN = 32
    secret = "crypto{p3n6u1n5"
    dic = ['_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'c', 'r', 'y', 'p', 't', 'o', '{', '}', 'a', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'q', 's', 'u', 'v', 'w', 'x', 'z']

    for i in range(16,SECRET_LEN+1):
        pad = "A"*(3*BLOCK_SIZE-i)
        for letter in dic:

            msg = pad+secret+letter+pad
            ciphertext = encrypt_with_oracle(msg.encode())

            #example of ciphertext: 75bf18aa6aba31885227cfcaff96282c54fb1963551628935151eb61b1f93bea, 2 16-bit blocks
            
            if ciphertext[64:96] == ciphertext[160:192]:
                print("Found new character = "+letter)
                secret+=letter
                print("Secret so far = "+secret)
                pad = pad[1:]
                break

    print("Secret discovered = "+secret)

