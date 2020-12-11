//
// Created by avacado on 2020/11/28.
//

#include "ModelProvider.h"

ModelProvider::ModelProvider(SEALContext context, double scale){
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    this->public_key = public_key;

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    this->relin_keys = relin_keys;

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    this->gal_keys = gal_keys;
}