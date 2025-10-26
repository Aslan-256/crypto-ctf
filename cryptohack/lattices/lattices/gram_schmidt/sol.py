# Gram Schmidt algorithm
import numpy as np

def gram_schmidt(basis):
    dim = len(basis[0])
    mu = np.zeros((len(basis), len(basis)))
    orthogonal_basis = basis.copy()
    for i in range(1, len(basis)):
        for j in range(i):
            mu[i][j] = np.dot(basis[i], orthogonal_basis[j]) / np.dot(orthogonal_basis[j], orthogonal_basis[j])
        sum = np.array([0, 0, 0, 0])
        for j in range(i):
            sum = sum + mu[i][j] * orthogonal_basis[j]
        orthogonal_basis[i] = basis[i] - sum
    return orthogonal_basis

# basis vectors
v1 = np.array([4, 1, 3, -1])
print(v1.shape)
v2 = np.array([2, 1, -3, 4])
v3 = np.array([1, 0, -2, 7])
v4 = np.array([6, 2, 9, -5])
basis = [v1, v2, v3, v4]
orthogonal_basis = gram_schmidt(basis)
for vec in orthogonal_basis:
    print(vec)

# actual flag
print(round(orthogonal_basis[3][1], 5))