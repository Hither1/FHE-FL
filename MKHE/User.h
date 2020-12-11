//
// Created by avacado on 2020/11/21.
//

#include "seal/seal.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>



using namespace seal;
using namespace seal::util;
using namespace std;

class User {
private:
    int id;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    double scale;
    vector<vector<double>> data;

    // We use a fresh memory pool with `clear_on_destruction' enabled.
    MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    void dot_product_ct_sk(SEALContext, const Ciphertext &, RNSIter, int, MemoryPoolHandle);




public:
    User(int, SEALContext, double); // To instantiate a new user
    Ciphertext encrypt(SEALContext);
    void partial_decrypt(SEALContext, Ciphertext, RNSIter);
    //vector<vector<double>>getData(SEALContext, string);
    // Using random data to test
    vector<double> getData(SEALContext);
};

