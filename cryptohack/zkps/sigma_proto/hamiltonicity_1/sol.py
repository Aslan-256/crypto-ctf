# archive.cryptohack.org 14635
from pwn import remote
import json
import random
from hamiltonicity import commit_to_graph, permute_graph, hash_committed_graph, comm_params

HOST = "archive.cryptohack.org"
PORT = 14635

numrounds = 128
N = 5

# The server's graph — it has NO Hamiltonian cycle.
# We will forge the proof by grinding the commitment so the Fiat-Shamir
# challenge always comes out 0 (reveal permutation), which we can always answer.
G = [
    [0,0,1,0,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,0,1,0]
]

def gen_A(G, N):
    """Commit to G, then shuffle the commitment matrix with a random permutation."""
    permutation = list(range(N))
    random.shuffle(permutation)
    A, openings = commit_to_graph(G, N)
    A_permuted = permute_graph(A, N, permutation)
    return A_permuted, openings, permutation

if __name__ == "__main__":
    r = remote(HOST, PORT)
    r.recvuntil(b'prove to me that G has a hamiltonian cycle!')

    FS_state = b''
    for i in range(numrounds):
        # Grind: regenerate fresh commitments until the FS hash gives challenge bit 0.
        # Challenge 0 asks us to open the full graph (easy).
        # Challenge 1 asks us to open a Hamiltonian cycle (impossible — graph has none).
        while True:
            A_permuted, openings, permutation = gen_A(G, N)
            new_state = hash_committed_graph(A_permuted, FS_state, comm_params)
            if (new_state[-1] & 1) == 0:
                break

        FS_state = new_state

        # Challenge 0: reveal permutation + permuted openings.
        # Server verifies: open_graph(A_permuted, openings_permuted) == permute_graph(G, permutation)
        openings_permuted = permute_graph(openings, N, permutation)
        z = [permutation, openings_permuted]

        r.recvuntil(b"send fiat shamir proof: ")
        r.sendline(json.dumps({"A": A_permuted, "z": z}).encode())
        resp = r.recvline()
        print(f"Round {i}: {resp.decode().strip()}'")

    print(r.recvall().decode())