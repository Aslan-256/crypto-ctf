from pwn import *
import json

r = remote('socket.cryptohack.org', 13399)

# def challenge(self, your_input):
#         if your_input['option'] == 'authenticate':
#             if 'password' not in your_input:
#                 return {'msg': 'No password provided.'}
#             your_password = your_input['password']
#             if your_password.encode() == self.password:
#                 self.exit = True
#                 return {'msg': 'Welcome admin, flag: ' + FLAG}
#             else:
#                 return {'msg': 'Wrong password.'}

#         if your_input['option'] == 'reset_connection':
#             self.cipher = CFB8(urandom(16))
#             return {'msg': 'Connection has been reset.'}

#         if your_input['option'] == 'reset_password':
#             if 'token' not in your_input:
#                 return {'msg': 'No token provided.'}
#             token_ct = bytes.fromhex(your_input['token'])
#             if len(token_ct) < 28:
#                 return {'msg': 'New password should be at least 8-characters long.'}

#             token = self.cipher.decrypt(token_ct)
#             new_password = token[:-4]
#             self.password_length = bytes_to_long(token[-4:])
#             self.password = new_password[:self.password_length]
#             return {'msg': 'Password has been correctly reset.'}

r.recvuntil(b'Please authenticate to this Domain Controller to proceed\n')
for i in range(512):
    print(f"Attempt {i}/255")
    payload = json.dumps({"option": "reset_password", "token": "00" * 28}).encode()
    r.sendline(payload)
    r.recvuntil(b'Password has been correctly reset.')
    payload = json.dumps({"option": "authenticate", "password": ""}).encode()
    r.sendline(payload)
    r.recvline()
    resp = r.recvline().decode()
    if "flag" in resp:
        print(resp)
        break
    else:
        # Wrong password, reset connection to get a new key 
        payload = json.dumps({"option": "reset_connection"}).encode()
        r.sendline(payload)

r.interactive()