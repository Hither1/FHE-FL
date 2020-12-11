from seal import *
from seal_helper import *
import numpy as np
import time

class Aggregator:
    def __init__(self, poly_modulus_degree):
        self.poly_modulus_degree = poly_modulus_degree

    def setup(self):
        parms = EncryptionParameters(scheme_type.CKKS)

        parms.set_poly_modulus_degree(self.poly_modulus_degree)
        parms.set_coeff_modulus(CoeffModulus.Create(
            self.poly_modulus_degree, [60, 40, 40, 60]))

        self.scale = pow(2.0, 40)
        self.context = SEALContext.Create(parms)
        print_parameters(self.context)

        self.keygen = KeyGenerator(self.context)
        self.public_key = self.keygen.public_key()
        self.secret_key = self.keygen.secret_key()
        self.relin_keys = self.keygen.relin_keys()

        self.encryptor = Encryptor(self.context, self.public_key)
        self.evaluator = Evaluator(self.context)
        self.decryptor = Decryptor(self.context, self.secret_key)

        self.encoder = CKKSEncoder(self.context)
        self.slot_count = self.encoder.slot_count()

    """
    Assume that the user inputs are 2-dimensional matrices of arbitrary sizes
    """

    def Add(self, *argv):
        inputs = []
        for arg in argv:
            inputs.append(arg)

        n = len(inputs[0])
        m = len(inputs[0][0])
        # Step 1: check that the dimension of the inputs are of the same dimension
        for i in range(1, len(inputs)):
            if len(inputs[i]) != n or len(inputs[i][0]) != m:
                raise Exception("The dimensions of the input matrices do not match.")

        # Step 2: Addition
        self.setup()
        encrypts = []
        for i in range(len(inputs)):
            vector = DoubleVector([item for sublist in inputs[i] for item in sublist])

            plain = Plaintext() # Initialize the plaintexts

            self.encoder.encode(vector, self.scale, plain) # Encoding

            encrypted = Ciphertext() # Initialize the ciphertexts

            self.encryptor.encrypt(plain, encrypted) # Encryption

            encrypts.append(encrypted)



        # Adding the ciphertexts

        if len(encrypts)<=1: # Case 1: If there is only one input matrix
            return encrypts[0]

        # Case 2: If there are at least 2 inputs
        encrypted_result = Ciphertext()
        self.evaluator.add(encrypts[0], encrypts[1], encrypted_result)
        for i in range(2, len(inputs)):
            self.evaluator.add_inplace(encrypted_result, encrypts[i])

        # TODO: Time the encryption process to see performance
        return encrypted_result


if __name__ == '__main__':
    # add_3_Scalars_bfv()
    # add_3_Scalars_ckks()
    # add_3_Matices_bfv(100)

    aggregator = Aggregator(8192)
    # Initialize 3 matrices as an example
    matrix_1 = [[0.0, 1.0], [1.0, 2.0]]
    matrix_2 = [[9.0, 7.0], [1.0, 2.0]]
    matrix_3 = [[0.0, 2.0], [3.0, 2.0]]

    result = aggregator.Add(matrix_1, matrix_2, matrix_3)

    # Check the correctness
    plain_result = Plaintext()
    aggregator.decryptor.decrypt(result, plain_result)

    # For debugging use
    print(aggregator.encoder.decode(plain_result)[4])