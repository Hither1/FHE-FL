//
// Created by avacado on 2020/11/21.
// A User instance each time when a new user is added to the training session.
//

#include <seal/util/polyarithsmallmod.h>
#include "User.h"
#include <seal/util/rlwe.h>

//#include "EasyXLS.h"

User::User(int id, SEALContext context, double scale) {

    this->id = id;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    this->secret_key = secret_key;

    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    this->public_key = public_key;

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    this->relin_keys = relin_keys;

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    this->gal_keys = gal_keys;

    this->scale = scale;

}


Ciphertext User::encrypt(SEALContext context) {

    auto &parms = context.first_context_data()->parms();

    // Get data
    vector<double> mydata;
    mydata = this->getData(context);


    // Set encryption utilities
    Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
    CKKSEncoder encoder(context);
    cout << "User Encode" << endl;
    encoder.encode(mydata, this->scale, plain);

    cout << "User Encrypt" << endl;
    Ciphertext encrypted(context);
    Encryptor encryptor(context, this->public_key);
    encryptor.encrypt(plain, encrypted);

    return encrypted;
}


void User::partial_decrypt(SEALContext context, Ciphertext cipher, RNSIter destination) {

    Plaintext destination_curr;

    //Decryptor decryptor(context, secret_key);

    if (!cipher.is_ntt_form())
    {
        throw invalid_argument("encrypted must be in NTT form");
    }

    // We already know that the parameters are valid
    auto &context_data = *context.get_context_data(cipher.parms_id());
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);



    // Decryption consists in finding
    // c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q_1 * q_2 * q_3
    // as long as ||m + v|| < q_1 * q_2 * q_3.
    // This is equal to m + v where ||v|| is small enough.

    // Since we overwrite destination, we zeroize destination parameters
    // This is necessary, otherwise resize will throw an exception.

    destination_curr.parms_id() = parms_id_zero;

    // Resize destination to appropriate size
    destination_curr.resize(rns_poly_uint64_count);
    // Do the dot product of encrypted and the secret key array using NTT.
    auto u(allocate_poly(coeff_count, coeff_modulus_size, pool_));
    // Create a PRNG; u and the noise/error share the same PRNG
    auto prng = parms.random_generator()->create();
    SEAL_NOISE_SAMPLER(prng, parms, u.get());


    dot_product_ct_sk(context, cipher, RNSIter(destination_curr.data(), coeff_count), this->id, pool_);
    destination_curr.resize(coeff_count);

    ConstRNSIter dest = destination;
    add_poly_coeffmod(dest, ConstRNSIter(destination_curr.data(), coeff_count), coeff_modulus_size, coeff_modulus, destination);

}


void User::dot_product_ct_sk(SEALContext context, const Ciphertext &encrypted, RNSIter destination, int userIndex, MemoryPoolHandle pool)
{
    cout << "dot_product_ct_sk" << endl;
    auto &context_data = *context.key_context_data();
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t key_coeff_modulus_size = context.key_context_data()->parms().coeff_modulus().size();


    // Use a iterator to find the polynomial in the ciphertext that we need
    auto const input_iter = iter(encrypted) + userIndex;

    // Setting secret_key_array
    cout << "Setting secret_key_array" << endl;
    Pointer<std::uint64_t> secret_key_array_;
    secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
    //set_poly(secret_key.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
    auto secret_key_array_iter = PolyIter(secret_key_array_.get(), coeff_count, key_coeff_modulus_size);
    cout << "Finished setting secret_key_array" << endl;

    // Multiply with secret key
    dyadic_product_coeffmod(*input_iter, *secret_key_array_iter, coeff_modulus_size, coeff_modulus, destination);


}


// vector<vector<double>> User::getData(SEALContext context, string Filename) {
// TODO: Sample a random row to represent this user
// }

vector<double> User::getData(SEALContext context) {

    //
    auto &parms = context.first_context_data()->parms();

    vector<double> user_data;
    random_device rd;
    for(size_t i = 0; i < 25; i++){
        user_data.push_back(1.001 * static_cast<double>(i));
    }

    return user_data;
}


