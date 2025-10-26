#size of v=(4,6,2,5)
import numpy as np

v = [4,6,2,5]
v_norm = 0
for i in range(4):
    v_norm = v_norm + v[i]*v[i]
print(np.sqrt(v_norm))