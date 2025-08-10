from pwn import * # pip install pwntools
import json
import base64
from Crypto.Util.number import bytes_to_long, long_to_bytes
import codecs

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

for i in range(100):
    received = json_recv()

    print("Received type: ")
    print(received["type"])
    print("Received encoded value: ")
    print(received["encoded"])

    match received["type"]:
        case "base64":
            decoded = base64.b64decode(received["encoded"]).decode()
        case "hex":
            decoded = bytes.fromhex(received["encoded"]).decode()
        case "rot13":
            decoded = codecs.decode(received["encoded"], 'rot_13')
        case "bigint":
            decoded = long_to_bytes(int(received["encoded"], 16)).decode()
        case "utf-8":
            decoded = ''.join(chr(b) for b in received["encoded"])

    print("Decoded value: ")
    print(decoded)

    to_send = {
        "decoded": decoded
    }
    json_send(to_send)

json_recv()
