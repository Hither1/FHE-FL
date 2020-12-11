from seal import *
from seal_helper import *
from PolynomialApproximation import PolynomialEvaluation_Horner
import time
def gradientDescent(func_evaluator, ciphers_y, cipher_h):
    '''
    cipher_h: Ciphertext of current predicted probability of default (param of the logistic model)
    cipher_y: data
    '''
    coeffs = [] # To store coefficients of polynomial

    # To compute some ciphertexts that can be reused
    plain_number_1 = Plaintext()
    plain_number_5 = Plaintext()
    plain_number_minus_5 = Plaintext()

    func_evaluator.ckks_encoder.encode(1.0, func_evaluator.scale, plain_number_1)
    func_evaluator.ckks_encoder.encode(5.0, func_evaluator.scale, plain_number_5)
    func_evaluator.ckks_encoder.encode(-5.0, func_evaluator.scale, plain_number_minus_5)

    cipher_number_1 = Ciphertext()
    cipher_number_5 = Ciphertext()
    cipher_number_minus_5 = Ciphertext()
    func_evaluator.encryptor.encrypt(plain_number_1, cipher_number_1)
    func_evaluator.encryptor.encrypt(plain_number_5, cipher_number_5)
    func_evaluator.encryptor.encrypt(plain_number_minus_5, cipher_number_minus_5)

    start = time.time()
    # coeff_0 = 1 - 5y
    cipher_0 = Ciphertext()
    func_evaluator.evaluator.multiply(cipher_number_minus_5, cipher_y, cipher_0) # -5 * y
    func_evaluator.evaluator.relinearize_inplace(cipher_0, func_evaluator.relin_keys)
    func_evaluator.evaluator.rescale_to_next_inplace(cipher_0)


    cipher_0.scale(func_evaluator.scale)
    cipher_number_1.scale(func_evaluator.scale)
    func_evaluator.evaluator.mod_switch_to_inplace(cipher_number_1, cipher_0.parms_id())
    func_evaluator.evaluator.add_inplace(cipher_0, cipher_number_1) # +1

    coeffs.append(cipher_0)

    # coeff_1 = 1 + 5y
    cipher_1 = Ciphertext()
    func_evaluator.evaluator.multiply(cipher_number_5, cipher_y, cipher_1)  # +5 * y
    func_evaluator.evaluator.relinearize_inplace(cipher_1, func_evaluator.relin_keys)
    func_evaluator.evaluator.rescale_to_next_inplace(cipher_1)

    cipher_1.scale(func_evaluator.scale)
    cipher_number_1.scale(func_evaluator.scale)
    func_evaluator.evaluator.mod_switch_to_inplace(cipher_number_1, cipher_0.parms_id())
    func_evaluator.evaluator.add_inplace(cipher_1, cipher_number_1)  # +1
    coeffs.append(cipher_1)

    # coeff_2 = 1 - 5y
    coeffs.append(cipher_0) # Since coeff_2 is always equal to coeff_0 in this case

    # coeff_3 = 1
    cipher_3 = cipher_number_1
    coeffs.append(cipher_3)

    end = time.time()
    print(end - start)
    return func_evaluator.horner(cipher_h, coeffs)


def gradientAscent(y, h, learning_rate=0.01, iterations=100):
    func_evaluator = PolynomialEvaluation_Horner()

def gradientDescent_test():
    func_evaluator = PolynomialEvaluation_Horner()
    func_evaluator.setup(degree=3)

    y = [1.0, 2.0, 3.0]
    ciphers_y = []
    for i in range(len(y)):
        plain_y = Plaintext()
        func_evaluator.ckks_encoder.encode(y[i], func_evaluator.scale, plain_y)
        cipher_y = Ciphertext()
        func_evaluator.encryptor.encrypt(plain_y, cipher_y)
        ciphers_y.append(cipher_y)


    h = 0.5 # Assume the current probability is 0.5
    plain_h = Plaintext()
    func_evaluator.ckks_encoder.encode(h, func_evaluator.scale, plain_h)
    cipher_h = Ciphertext()
    func_evaluator.encryptor.encrypt(plain_h, cipher_h)

    # Gradient Descent
    cipher_result = gradientDescent(func_evaluator, ciphers_y, cipher_h)

    plain_result = Plaintext()
    result = DoubleVector()
    func_evaluator.decryptor.decrypt(cipher_result, plain_result)
    func_evaluator.ckks_encoder.decode(plain_result, result)


    expected_result = h**3 + (1-5*y)*h**2 + (1+5*y)*h + (1-5*y)
    print("Actual : " + str(result[0]))
    print("Expected : " + str(expected_result))
    print("diff: " + str(abs(result[0] - expected_result)))

if __name__ == "__main__":
    gradientDescent_test()