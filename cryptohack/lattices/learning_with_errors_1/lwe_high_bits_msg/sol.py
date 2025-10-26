# parameters
n = 64 # dimension
p = 257 #2^8+1 plaintext modulus
q = 0x10001 #2^16+1 ciphertext modulus
delta = int(round(q/p)) #2^8=256 message scaling factor

# output
S =  (55542, 19411, 34770, 6739, 63198, 63821, 5900, 32164, 51223, 38979, 24459, 10936, 17256, 20215, 35814, 42905, 53656, 17000, 1834, 51682, 43780, 22391, 33012, 61667, 37447, 16404, 58991, 61772, 44888, 43199, 32039, 26885, 17206, 62186, 58387, 57048, 38393, 29306, 58001, 57199, 33472, 56572, 53429, 62593, 14134, 40522, 25106, 34325, 37646, 43688, 14259, 24197, 33427, 43977, 18322, 38877, 55093, 12466, 16869, 25413, 54773, 59532, 62694, 13948) 
A =  (13759, 12750, 38163, 63722, 39130, 22935, 58866, 48803, 15933, 64995, 60517, 64302, 42432, 32000, 22058, 58123, 53993, 33790, 35783, 61333, 53431, 43016, 60795, 25781, 28091, 11212, 64592, 11385, 24690, 40658, 35307, 63583, 60365, 60359, 32568, 35417, 22078, 38207, 16331, 53636, 28734, 30436, 18170, 15939, 966, 48519, 41621, 36371, 41836, 4026, 33536, 57062, 52428, 59850, 476, 43354, 61614, 32243, 42518, 19733, 63464, 29357, 56039, 15013)
b =  44007

# Decryption given ciphertext (A,b):
# Compute x=b−⟨A,S⟩modq and then interpret x as an integer (not modulo q)
# Compute m=round(x/Δ), where the division and rounding happens over the integers
# return m

def lwe_decrypt(A, b, S, delta, q):
    n = len(S)
    # Compute the inner product <A, S>
    inner_product = sum(A[i] * S[i] for i in range(n)) % q
    # Compute x = b - <A, S> mod q
    x = (b - inner_product) % q
    # Compute m = round(x / delta)
    m = round(x / delta)
    return m

m = lwe_decrypt(A, b, S, delta, q) 
print(m)