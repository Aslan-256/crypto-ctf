from PIL import Image
import numpy as np

lemur_img = Image.open('./lemur.png').convert('RGB')
flag_img = Image.open('./flag.png').convert('RGB')
lemur_arr = np.array(lemur_img)
flag_arr = np.array(flag_img)
sol = np.bitwise_xor(lemur_arr, flag_arr)
sol_img = Image.fromarray(sol)
sol_img.save('./lemur_xor_flag.png')
print("XOR operation completed and saved as lemur_xor_flag.png")