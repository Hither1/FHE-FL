from seal import *
from seal_helper import *
import numpy as np
import random
import math

class PolynomialEvaluation_Horner:
    def __init__(self, poly_modulus_degree=32768):
        self.poly_modulus_degree = poly_modulus_degree

    def setup(self, degree):
        parms = EncryptionParameters(scheme_type.CKKS)
        parms.set_poly_modulus_degree(self.poly_modulus_degree)

        moduli = np.ones(degree + 4, dtype=int) * 40
        moduli[0] = 50
        moduli[len(moduli) - 1] = 59

        parms.set_coeff_modulus(CoeffModulus.Create(
            self.poly_modulus_degree, moduli))

        self.scale = pow(2.0, 40)
        self.context = SEALContext.Create(parms)

        # Generate keys, encryptor, decryptor, evaluator
        self.keygen = KeyGenerator(self.context)
        self.public_key = self.keygen.public_key()
        self.secret_key = self.keygen.secret_key()
        self.relin_keys = self.keygen.relin_keys()
        # self.galois_keys = self.keygen.galois_keys()

        self.ckks_encoder = CKKSEncoder(self.context)
        self.slot_count = self.ckks_encoder.slot_count()
        self.encryptor = Encryptor(self.context, self.public_key)
        self.evaluator = Evaluator(self.context)
        self.decryptor = Decryptor(self.context, self.secret_key)


    '''
        ciphertext: Ciphertext
        degree: int
        powers: a vector of ciphertexts
        coeffs: a vector of coefficients
    '''
    # Horner's method for polynomial evaluation
    def horner(self, cipher_x, cipher_coeffs):
        # Infer degree from coeffs
        degree = len(cipher_coeffs) - 1 # A degree n polynomial has n + 1 coeffs

        temp = cipher_coeffs[degree]


        i = degree - 1
        while i >= 0:
            #expected_result *= x
            self.evaluator.mod_switch_to_inplace(cipher_x, temp.parms_id())
            self.evaluator.multiply_inplace(temp, cipher_x)

            # relinearize
            self.evaluator.relinearize_inplace(temp, self.relin_keys)
            self.evaluator.rescale_to_next_inplace(temp)
            # rescale
            #self.evaluator.rescale_to_next_inplace(temp)

            # Manual rescale
            temp.scale(pow(2.0, 40))
            cipher_coeffs[i].scale(pow(2.0, 40))

            self.evaluator.mod_switch_to_inplace(cipher_coeffs[i], temp.parms_id())
            self.evaluator.add_inplace(temp, cipher_coeffs[i])
            self.evaluator.relinearize_inplace(temp, self.relin_keys)


            i -= 1

        print("Evalution done")


        return temp






class PolynomialEvaluation_Tree:
    def __init__(self, poly_modulus_degree=16384):
        self.poly_modulus_degree = poly_modulus_degree

    def setup(self, degree):
        parms = EncryptionParameters(scheme_type.CKKS)
        parms.set_poly_modulus_degree(self.poly_modulus_degree)

        depth = math.ceil(math.log2(degree))

        moduli = np.ones(degree + 4, dtype=int) * 40
        moduli[0] = 50
        moduli[len(moduli) - 1] = 59

        parms.set_coeff_modulus(CoeffModulus.Create(
            self.poly_modulus_degree, moduli))

        self.scale = pow(2.0, 40)
        self.context = SEALContext.Create(parms)

        # Generate keys, encryptor, decryptor, evaluator
        self.keygen = KeyGenerator(self.context)
        self.public_key = self.keygen.public_key()
        self.secret_key = self.keygen.secret_key()
        self.relin_keys = self.keygen.relin_keys()
        # self.galois_keys = self.keygen.galois_keys()

        self.ckks_encoder = CKKSEncoder(self.context)
        self.slot_count = self.ckks_encoder.slot_count()
        self.encryptor = Encryptor(self.context, self.public_key)
        self.evaluator = Evaluator(self.context)
        self.decryptor = Decryptor(self.context, self.secret_key)

    '''
        ciphertext: Ciphertext
        degree: int
        powers: a vector of ciphertexts
    '''
    def compute_all_powers(self, ciphertext, degree, powers):

        powers[1] = ciphertext

        levels = np.zeros(degree+1)

        for i in range(2, degree+1):
            minlevel = i;

            cand = -1;

            for j in range(1, int(i/2) + 1):
                k = i - j
                newlevel = max(levels[j], levels[k]) + 1
                if newlevel < minlevel:
                    cand = j
                    minlevel = newlevel
            levels[i] = minlevel

            if cand < 0:
                raise Exception('Runtime Error!')

            temp = powers[cand]
            self.evaluator.mod_switch_to_inplace(temp, powers[i-cand].parms_id())

            self.evaluator.multiply(temp, powers[i - cand], powers[i])
            self.evaluator.relinearize_inplace(powers[i], self.relin_keys)
            self.evaluator.rescale_to_next_inplace(powers[i])

    # Tree method
    def tree(self, degree, x):
        ptx = Plaintext()

        self.ckks_encoder.encode(x, self.scale, ptx)

        ctx = Ciphertext()
        self.encryptor.encrypt(ptx, ctx)

        coeffs = np.zeros(degree+1)
        plain_coeffs = [] # To store Plaintexts

        print("Polynomial = ")
        counter = 0

        for i in range(degree + 1):
            coeffs[i] = random.random()
            plain_coeff = Plaintext()
            self.ckks_encoder.encode(coeffs[i], self.scale, plain_coeff)
            plain_coeffs.append(plain_coeff)

            print("x^" + str(counter) + " * (" + str(coeffs[i]) + ")" + ", ")
            counter += 1

        plain_result = Plaintext()
        result = DoubleVector()

        expected_result = coeffs[degree]

        # Compute all powers
        ctx_placeholder = Ciphertext()
        powers = [ctx_placeholder] * (degree + 1)

        self.compute_all_powers(ctx, degree, powers)
        print("All powers computed ")

        enc_result = Ciphertext()
        print("Encrypt first coeff...")
        self.encryptor.encrypt(plain_coeffs[0], enc_result)
        print("Done")

        temp = Ciphertext()

        for i in range(1, degree+1):
            self.evaluator.mod_switch_to_inplace(plain_coeffs[i], powers[i].parms_id())
            self.evaluator.multiply_plain(powers[i], plain_coeffs[i], temp)

            self.evaluator.rescale_to_next_inplace(temp)
            self.evaluator.mod_switch_to_inplace(enc_result, temp.parms_id())

            # Manual Rescale
            enc_result.scale(pow(2.0, 40))
            temp.scale(pow(2.0, 40))

            self.evaluator.add_inplace(enc_result, temp)

        print("Evaluation done")

        # Compute expected result
        for i in range(degree-1, -1, -1):
            expected_result *= x
            expected_result += coeffs[i]

        self.decryptor.decrypt(enc_result, plain_result)
        self.ckks_encoder.decode(plain_result, result)

        print("Actual : " + str(result[0]))
        print("Expected : " + str(expected_result))
        print("diff: " + str(abs(result[0] - expected_result)))


def horner_test():
    poly_evaluator_horner = PolynomialEvaluation_Horner()  # Use default
    degree = 3
    x = 2
    poly_evaluator_horner.setup(degree)

    print("test Horner method")
    poly_evaluator_horner.horner(degree, x)

def tree_test():
    poly_evaluator_tree = PolynomialEvaluation_Tree()  # Use default
    degree = 2
    x = 2
    poly_evaluator_tree.setup(degree)

    print("test Tree method")
    poly_evaluator_tree.tree(degree, x)

if __name__ == '__main__':
    # horner_test()
    tree_test()



