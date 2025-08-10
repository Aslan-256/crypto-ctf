from Crypto.PublicKey import RSA 
from Crypto.Util.number import bytes_to_long
import base64

pem_key = RSA.import_key(open('./privacy_enhanced_mail.pem').read())
private_key = pem_key.export_key().decode('utf-8')
#Extract the private key d as a decimal integer from this PEM-formatted RSA key.

d = pem_key.d  # Extract the private exponent d
print(f"Private Exponent (d): {d}")
