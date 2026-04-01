from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

N = 22266616657574989868109324252160663470925207690694094953312891282341426880506924648525181014287214350136557941201445475540830225059514652125310445352175047408966028497316806142156338927162621004774769949534239479839334209147097793526879762417526445739552772039876568156469224491682030314994880247983332964121759307658270083947005466578077153185206199759569902810832114058818478518470715726064960617482910172035743003538122402440142861494899725720505181663738931151677884218457824676140190841393217857683627886497104915390385283364971133316672332846071665082777884028170668140862010444247560019193505999704028222347577
e = 3

r = remote('socket.cryptohack.org', 13375)

vote_end = b'\00' + b'VOTE FOR PEDRO'

# ============================================================================
# Small Field Reduction (from root.py)
# ============================================================================
# We can reduce the computation in the field Z/kZ with k = 256^len(vote_end) 
# since we only care about the last bytes of the vote
root = 855520592299350692515886317752220783
# ============================================================================

# we can now simply add multiples of k till we find a perfect cube
while True:
    if check_ending(root**e, vote_end):
        print("Found a valid vote signature:", root)
        break
    root += 256 ** len(vote_end)

root_hex = hex(root)[2:]

r.recvuntil(b'him!\n')
r.sendline(b'{"option": "vote", "vote": "' + root_hex.encode() + b'"}')

print(r.recvline())
r.close()