//
// Created by Huangyuan Su on 2020/11/21.
//

#include "Session.h"
#include "seal/seal.h"
#include <seal/util/polyarithsmallmod.h>


using namespace seal;
using namespace seal::util;
/*
 * Constructor
 * */
Session::Session(int numberOfUsers) {
    this->numberOfUsers = numberOfUsers;
}

/*
 * This
 * */
void Session::setSecurityParameter(int securityParameter){
    SecurityParameter = securityParameter;
}

/*
 * This
 * */
void Session::Start() {
    // Set public parameters
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);
    SEALContext context(parms);

    // Initialize users
    for(int i = 0; i < this->numberOfUsers; i++){
        cout<< "Adding User " + std::to_string(i) << endl;
        User newUser(i+1, context, scale);
        this->SessionUsers.push_back(newUser);
    }

    // Initialize model provider
    cout<< "Adding Model Provider" << endl;
    ModelProvider modelProvider();

    // Initialize server
    cout << "" << endl;
    Server server(this->numberOfUsers, scale);

    // 0. Encrypt user input data
    vector<Ciphertext> ciphers;
    vector<set<int>> indexes(numberOfUsers);

    cout<< "Encrypting" << endl;
    for(int i = 0; i < this->numberOfUsers; i++){
        Ciphertext cipher;
        cipher = SessionUsers[i].encrypt(context);
        ciphers.push_back(cipher);
        indexes[i].insert(i + 1);
    }

    // 1. Perform an Addition
    // Do Preprocessing First
    cout<< "Performing Addition" << endl;
    Ciphertext addition_result; // Encrypt
    cout<< "Processing & Adding the First two" << endl;
    preprocessing(context, ciphers[0], indexes[0], ciphers[1], indexes[1]);
    server.Add(context, ciphers[0], ciphers[1], addition_result);
    set<int> index_addition_result = {1, 2};

    // Adding all the remaining ciphertexts
    for(size_t i = 2; i < this->numberOfUsers; i++){

        cout << "Preprocessing round " + std::to_string(i) << endl;
        preprocessing(context, ciphers[i], indexes[i], addition_result, index_addition_result);
        //cout << addition_result << endl;
        cout << "Addition round " + std::to_string(i) << endl;
        server.Add(context, ciphers[i], addition_result, addition_result);

    }


    // 2.

    // 3. Decryption

    //RNSIter destination;
    if(addition_result.size() != numberOfUsers + 1){
        cout << "Ciphertext size is " + to_string(addition_result.size()) << endl;
        throw invalid_argument("Invalid cipher size");
    }
    // To collect partial decryption results from users
    auto &context_data = *context.get_context_data(addition_result.parms_id());
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);

    cout << "rns_poly " + to_string(rns_poly_uint64_count) << endl;
    Plaintext destination;
    destination.resize(rns_poly_uint64_count);
    destination.parms_id() = parms_id_zero;

    for(size_t i=0; i < numberOfUsers; i++){
        cout << "Partial decryption round " + to_string(i) << endl;
        SessionUsers[i].partial_decrypt(context, addition_result, RNSIter(destination.data(), coeff_count));
        cout << "coeff_count of dest " + to_string(destination.coeff_count()) << endl;
    }
    // Add c_0
    cout << "Adding c_0" << endl;
    add_poly_coeffmod(RNSIter(destination.data(), coeff_count), *iter(addition_result), coeff_modulus_size, coeff_modulus, RNSIter(destination.data(), coeff_count));

    vector<double> final_result;

    destination.resize(coeff_count);
    cout << "coeff_count of dest after resizing " + to_string(destination.coeff_count()) << endl;

    Evaluator evaluator(context);
    //evaluator.mod_switch_to_inplace(destination, addition_result.parms_id());
    cout << "After mod switch..." << endl;


    CKKSEncoder encoder(context);
    cout << "Decoding..." << endl;

    auto &parm = context.first_context_data()->parms();
    const Plaintext::pt_coeff_type *ptr = destination.data();
    uint64_t modulus = parm.plain_modulus().value();
    auto size = destination.coeff_count();
    for (size_t k = 0; k < size; k++, ptr++)
    {
        if (*ptr >= modulus)
        {
            cout << to_string(*ptr) << endl;
            cout << to_string(modulus) << endl;
            cout << "plain modulus is larger" << endl;
        }
    }

    encoder.decode(destination, final_result);
    for(size_t i=0; i < 25; i++){
        cout << "Decoded result: " + to_string(final_result[i]) + " ";
    }
    cout << endl;

}

void Session::preprocessing(SEALContext context, seal::Ciphertext &cipher1, set<int> &index1, seal::Ciphertext &cipher2, set<int> &index2){
    //vector<int> index_result(1);
    //std::set_union(index1.begin(), index1.end(), index2.begin(), index2.end(), index_result.begin());

    if (!cipher1.is_ntt_form() || !cipher1.is_ntt_form())
    {
        throw invalid_argument("encrypted must be in NTT form");
    }


    for(auto it=index2.cbegin(); it != index2.cend(); ++it){
        if(find(index1.begin(), index1.end(), *it) == index1.end()){
            index1.insert(*it);
        }
    }
    cout << "Size is " + to_string(index1.size()) << endl;
    size_t dest_size = add_safe(index1.size(), size_t(1)) ;
    auto &context_data = *context.get_context_data(cipher1.parms_id());
    Ciphertext temp1, temp2;
    temp1.resize(context, context_data.parms_id(), dest_size);
    temp2.resize(context, context_data.parms_id(), dest_size);

    // Set up iterator for input ciphertexts
    auto input1_iter = iter(cipher1);
    auto input2_iter = iter(cipher2);

    // Set up iterator for output ciphertexts
    auto output1_iter = iter(temp1);
    auto output2_iter = iter(temp2);

    // c_0* = c_0
    ***output1_iter = ***input1_iter;
    ***output2_iter = ***input2_iter;

    //
    output1_iter++;
    output2_iter++;
    input1_iter++;
    input2_iter++;
    //
    for(int i=1; i < index1.size(); i++){

        // If Ciphertext 1 contains a poly encrypted by PublicKey i
        if(std::find(index1.begin(), index1.end(), i) != index1.end()){
            ***output1_iter = ***input1_iter;
            input1_iter++;
            output1_iter++;
        }else{ // If not
            ***output1_iter = 0;
            output1_iter++;
        }

        // If Ciphertext 2 contains a poly encrypted by PublicKey i
        if(std::find(index2.begin(), index2.end(), i) != index2.end()){
            ***output2_iter = ***input2_iter;
            input2_iter++;
            output2_iter++;
        }else{ // If not
            ***output2_iter = 0;
            output2_iter++;
        }
    }

    index2 = index1;
    cipher1 = temp1;
    cipher2 = temp2;

    Evaluator evaluator(context);
    evaluator.transform_to_ntt_inplace(cipher1);
    evaluator.transform_to_ntt_inplace(cipher2);
    if (!cipher1.is_ntt_form() || !cipher2.is_ntt_form())
    {
        throw invalid_argument("encrypted must be in NTT form");
    }
}

