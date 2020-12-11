//
// Created by avacado on 2020/11/28.
//

#include "seal/seal.h"
#include "seal/encryptor.h"


using namespace seal;
using namespace std;

class ModelProvider {
private:
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;

public:
    ModelProvider(SEALContext, double);
};


