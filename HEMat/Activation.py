from seal import *
from seal_helper import *
from PolynomialApproximation import PolynomialEvaluation_Horner


'''
function to evaluate sigmoid in an Encrypted way
cipher_x: Ciphertext for the value on which we will evaluate sigmoid function at
'''
def sigmoid(func_evaluator, cipher_x):
    coeffs = []
    coeffs.append(1.0/2) #coeff_0
    coeffs.append(1.0/4) #coeff_1
    coeffs.append(0) #coeff_2
    coeffs.append(-1.0/48) #coeff_3
    coeffs.append(0) #coeff_4
    coeffs.append(1.0/480) #coeff_5
    coeffs.append(0) #coeff_6
    coeffs.append(-17.0/80640) #coeff_7

    cipher_coeffs = []
    for i in range(len(coeffs)):
        plain = Plaintext()
        func_evaluator.ckks_encoder.encode(coeffs[i], func_evaluator.scale, plain)
        cipher = Ciphertext()
        func_evaluator.encryptor.encrypt(plain, cipher)

    return func_evaluator.horner(cipher_x, cipher_coeffs)


def sigmoid_test():
    func_evaluator = PolynomialEvaluation_Horner()
    func_evaluator.setup(7)
    x = 1
    plain_x = Plaintext()
    func_evaluator.ckks_encoder.encode(x, func_evaluator.scale, plain_x)
    cipher_x = Ciphertext()
    func_evaluator.encryptor.encrypt(plain_x,cipher_x)

    cipher_result = sigmoid(func_evaluator, cipher_x)
    plain_result = Plaintext()
    result = DoubleVector()
    func_evaluator.decryptor.decrypt(cipher_result, plain_result)
    func_evaluator.ckks_encoder.decode(plain_result, result)

    expected_result = 1.0/2 + x * 1.0/4 - x**3 * 1.0/48 + x**5 * 1.0/480 - x**7 * 17.0/80640
    print("Actual : " + str(result[0]))
    print("Expected : " + str(expected_result))
    print("diff: " + str(abs(result[0] - expected_result)))


if __name__ == "__main__":
    sigmoid_test()