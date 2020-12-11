from seal import *
from seal_helper import *

import numpy as np
import xlrd
import time
# To test how long does it take on average to encrypt raw data

wb = xlrd.open_workbook('../data/credit_card_demographics.xls')

general_sheet = wb.sheet_by_name('general')

# Converting it to a Numpy array
general = np.zeros((general_sheet.nrows, general_sheet.ncols))
curr_row = 0
while curr_row < general_sheet.nrows: # for each row

    row = general_sheet.row(curr_row)
    if curr_row > 0: # don't want the first row because those are labels
        for col_ind, el in enumerate(row):
            general[curr_row, col_ind] = el.value
    curr_row += 1


general = general.flatten()[0:100]
print(len(general))
# Set up the encryption parameters
parms = EncryptionParameters(scheme_type.CKKS)

poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(
    poly_modulus_degree, [60, 40, 40, 60]))

scale = pow(2.0, 40)
context = SEALContext.Create(parms)
print_parameters(context)

keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
relin_keys = keygen.relin_keys()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

encoder = CKKSEncoder(context)
slot_count = encoder.slot_count()
print("Slot count: "+str(slot_count))

# 1. Encrypt all data
start = time.time()

# Encode
plain = Plaintext()
plain = encoder.encode(general, scale)

# Encrypt
cipher = Ciphertext()
encryptor.encrypt(plain, cipher)

end = time.time()

print("Time used by encrypting the whole trunk: "+ str(end - start))
# Store into file
f = open("../encrypted_data.txt","w+") # 39 Bytes for 4096 cells

f.write(str(cipher))

ciphers = [] # To store the Ciphertexts
for i in range(len(general)):
    plain = Plaintext()
    encoder.encode(general[i], scale, plain)
    cipher = Ciphertext()
    encryptor.encrypt(plain, cipher)
    ciphers.append(cipher)

# 2. Addition, For loop
plain_number_1 = Plaintext()
encoder.encode(1.0, scale, plain_number_1)
cipher_number_1 = Ciphertext()
encryptor.encrypt(plain_number_1, cipher_number_1)

start = time.time()
for i in range(len(general)):
    evaluator.add_inplace(ciphers[i], cipher_number_1)

end = time.time()
print("Time used by " + str(100) + " ddition, Loop: " + str(end - start))

# 3. Multiplication, For loop
start = time.time()
for i in range(len(general)):
    evaluator.multiply_inplace(ciphers[i], cipher_number_1)

end = time.time()
print("Time used by " + str(100) + " Multiplication, Loop: " + str(end - start))