####################### Gauss Lattice Attack #######################
import numpy as np
from Crypto.Util.number import long_to_bytes, inverse

def gauss_reduction(v, u):
    while True:
        if np.dot(u, u) < np.dot(v, v):
            v, u = u, v
        m = round(np.dot(v, u) / np.dot(v, v))
        if m == 0:
            break
        u = u - m * v
    return v, u

q, h = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
e = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

# h = (g * f_inv) % q   => 
# g = (h * f) % q       =>
# g = h * f + k * q
# moreover, f and g are small, so we may use
# the lattice reduction on a special basis to find them. 
#
# possible basis:
# v = (q, 0)
# u = (h, 1)
#
# v*k + u*f = (q*k + h*f, f) = (g, f)

v = np.array([q, 0])
u = np.array([h, 1])
v, u = gauss_reduction(v, u)
lower_bound = int(np.sqrt(float(q) // 4))
upper_bound = int(np.sqrt(float(q) // 2))
assert lower_bound <= abs(v[0]) <= upper_bound
# assert lower_bound <= abs(u[0]) <= upper_bound
# only v[0] is in the range, so v = (g, f)
g = v[0]
f = v[1]
m = (f * e) % q
m = (m * inverse(f, g)) % g
print(long_to_bytes(m))  # crypto{lattices_are_fun_and_useful}
