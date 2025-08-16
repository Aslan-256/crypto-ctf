# Key Notes

These are the main concepts that helped me solve the exercises:

## Lazy CBC
- Pay attention to the information leaked by the server: even if the padding is incorrect, the server’s response may still include the ciphertext in hexadecimal form, which can reveal useful details.

## Triple DES
- The DES algorithm has some weak keys: in specific cases (e.g., with keys like `00000000FFFFFFFF`), a second encryption can act as a decryption.
