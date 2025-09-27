# Take the two vectors v=(846835985,9834798552),u=(87502093,123094980) and by applying Gauss's algorithm, find the optimal basis. The flag is the inner product of the new basis vectors.
import numpy as np

def gauss_reduction(v, u):
    while True:
        if np.linalg.norm(u) < np.linalg.norm(v):
            v, u = u, v
        m = round(np.dot(v, u) / np.dot(v, v))
        if m == 0:
            break
        u = u - m * v
    return v, u

v = np.array([846835985, 9834798552])
u = np.array([87502093, 123094980])
v, u = gauss_reduction(v, u)
print(np.dot(v, u))