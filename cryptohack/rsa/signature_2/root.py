from sage.all import *

vote_end = 1750572331061789800727934052618831
vote_end_bytes_len = 15
e = 3

# ============================================================================
# Small Field Reduction
# ============================================================================
# We can reduce the computation in the field Z/kZ with k = 256^len(vote_end) 
# since we only care about the last bytes of the vote
k = 256 ** vote_end_bytes_len
print("k", k)
# We want to find a vote such that vote^3 = vote_end (mod k)
field = Zmod(k)
vote_signature = field(vote_end).nth_root(e)
print("vote signature", vote_signature)
print("vote signature^3", vote_signature**e)
