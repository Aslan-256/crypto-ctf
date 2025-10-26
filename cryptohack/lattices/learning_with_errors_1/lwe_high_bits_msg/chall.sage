# dimension
n = 64
# plaintext modulus
p = 257 #2^8+1
# ciphertext modulus
q = 0x10001 #2^16+1
# bound for error term
error_bound = int(floor((q/p)/2)) #2^7=128
# message scaling factor
delta = int(round(q/p)) #2^8=256


V = VectorSpace(GF(q), n)
S = V.random_element()
print("S = ", S, "\n")

m = ?

A = V.random_element()
error = randint(-error_bound, error_bound)
b = A * S + m * delta + error

print("A = ", A)
print("b = ", b)
