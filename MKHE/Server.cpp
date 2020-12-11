//
// Created by avacado on 2020/11/30.
//

#include "Server.h"
#include "helper.h"

Server::Server(int numberOfUsers, double scale){
    this->scale = scale;
    this->numberOfUsers = numberOfUsers;
}
/*
Ciphertext Server::CC_Matrix_Multiplication(Ciphertext ctA, Ciphertext ctB, int dimension, vector<Plaintext> U_sigma_diagonals, vector<Plaintext> U_tau_diagonals, vector<vector<Plaintext>> V_diagonals, vector<vector<Plaintext>> W_diagonals, GaloisKeys gal_keys, EncryptionParameters params)
{

    auto context = SEALContext::Create(params);
    Evaluator evaluator(context);

    vector<Ciphertext> ctA_result(dimension);
    vector<Ciphertext> ctB_result(dimension);

    cout << "----------Step 1----------- " << endl;
    // Step 1-1
    ctA_result[0] = Linear_Transform_Plain(ctA, U_sigma_diagonals, gal_keys, params);

    // Step 1-2
    ctB_result[0] = Linear_Transform_Plain(ctB, U_tau_diagonals, gal_keys, params);

    // Step 2
    cout << "----------Step 2----------- " << endl;

    for (int k = 1; k < dimension; k++)
    {
        cout << "Linear Transf at k = " << k;
        ctA_result[k] = Linear_Transform_Plain(ctA_result[0], V_diagonals[k - 1], gal_keys, params);
        ctB_result[k] = Linear_Transform_Plain(ctB_result[0], W_diagonals[k - 1], gal_keys, params);
        cout << "..... Done" << endl;
    }


    // Step 3
    cout << "----------Step 3----------- " << endl;

    // Test Rescale
    cout << "RESCALE--------" << endl;
    for (int i = 1; i < dimension; i++)
    {
        evaluator.rescale_to_next_inplace(ctA_result[i]);
        evaluator.rescale_to_next_inplace(ctB_result[i]);
    }


    Ciphertext ctAB;
    evaluator.multiply(ctA_result[0], ctB_result[0], ctAB);

    // cout << "TEST" << endl;
    // cout << "CTAB scale :\t" << log2(ctAB.scale()) << endl;
    // cout << "CTAB chain index :\t" << context->get_context_data(ctAB.parms_id())->chain_index() << endl;

    // Mod switch CTAB
    // cout << "MOD SWITCH CTAB:" << endl;
    evaluator.mod_switch_to_next_inplace(ctAB);
    // cout << "CTAB chain index :\t" << context->get_context_data(ctAB.parms_id())->chain_index() << endl;

    // Manual scale set
    cout << "\nMANUAL SCALE:" << endl;
    for (int i = 1; i < dimension; i++)
    {
        ctA_result[i].scale() = pow(2, (int)log2(ctA_result[i].scale()));
        ctB_result[i].scale() = pow(2, (int)log2(ctB_result[i].scale()));
    }

    for (int k = 1; k < dimension; k++)
    {
        cout << "Iteration k = " << k << endl;
        Ciphertext temp_mul;
        evaluator.multiply(ctA_result[k], ctB_result[k], temp_mul);
        evaluator.add_inplace(ctAB, temp_mul);
    }

    return ctAB;
}

Ciphertext Server::MatrixMultiplication(Ciphertext cipher1, Ciphertext cipher2, SEALContext context, int dimension) {

    auto &parms = context.first_context_data()->parms();
    auto &plain_modulus = parms.plain_modulus();
    auto &poly_modulus_degree = parms.poly_modulus_degree();

    // Handle Rotation Error First
    if (dimension > poly_modulus_degree / 4)
    {
        cerr << "Dimension is too large. Choose a dimension less than " << poly_modulus_degree / 4 << endl;
        exit(1);
    }

    Evaluator evaluator(context);


    int dimensionSq = pow(dimension, 2);

    // Get U_sigma for first matrix
    vector<vector<double>> U_sigma = get_U_sigma(pod_matrix1_set1);
    cout << "\nU_sigma:" << endl;
    print_full_matrix(U_sigma, 0);

    // Get U_tau for second matrix
    vector<vector<double>> U_tau = get_U_tau(pod_matrix1_set1);
    cout << "\nU_tau:" << endl;
    print_full_matrix(U_tau, 0);

    // Get V_k (3D matrix)
    vector<vector<vector<double>>> V_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k[i - 1] = get_V_k(pod_matrix1_set1, i);
        cout << "\nV_" << to_string(i) << ":" << endl;
        print_full_matrix(V_k[i - 1], 0);
    }

    // Get W_k (3D matrix)
    vector<vector<vector<double>>> W_k(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k[i - 1] = get_W_k(pod_matrix1_set1, i);
        cout << "\nW_" << to_string(i) << ":" << endl;
        print_full_matrix(W_k[i - 1], 0);
    }

    // Get Diagonals for U_sigma
    vector<vector<double>> U_sigma_diagonals = get_all_diagonals(U_sigma);
    cout << "U_sigma Diagonal Matrix:" << endl;
    print_full_matrix(U_sigma_diagonals, 0);

    // Test ADD EPSILON
    double epsilon = 0.00000001;
    for (int i = 0; i < dimensionSq; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            U_sigma_diagonals[i][j] += epsilon;
        }
    }

    // Get Diagonals for U_tau
    vector<vector<double>> U_tau_diagonals = get_all_diagonals(U_tau);

    // Test ADD EPSILON
    for (int i = 0; i < dimensionSq; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            U_tau_diagonals[i][j] += epsilon;
        }
    }

    // Get Diagonals for V_k
    vector<vector<vector<double>>> V_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        V_k_diagonals[i - 1] = get_all_diagonals(V_k[i - 1]);
    }

    // Test ADD EPSILON
    for (int i = 0; i < dimension - 1; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            for (int k = 0; k < dimensionSq; k++)
            {

                V_k_diagonals[i][j][k] += epsilon;
            }
        }
    }

    // Get Diagonals for W_k
    vector<vector<vector<double>>> W_k_diagonals(dimension - 1, vector<vector<double>>(dimensionSq, vector<double>(dimensionSq)));

    for (int i = 1; i < dimension; i++)
    {
        W_k_diagonals[i - 1] = get_all_diagonals(W_k[i - 1]);
    }

    // Test ADD EPSILON
    for (int i = 0; i < dimension - 1; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            for (int k = 0; k < dimensionSq; k++)
            {

                W_k_diagonals[i][j][k] += epsilon;
            }
        }
    }

    // --------------- ENCODING ----------------
    // Encode U_sigma diagonals
    vector<Plaintext> U_sigma_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_sigma_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_sigma_diagonals[i], scale, U_sigma_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode U_tau diagonals
    vector<Plaintext> U_tau_diagonals_plain(dimensionSq);
    cout << "\nEncoding U_tau_diagonals...";
    for (int i = 0; i < dimensionSq; i++)
    {
        ckks_encoder.encode(U_tau_diagonals[i], scale, U_tau_diagonals_plain[i]);
    }
    cout << "Done" << endl;

    // Encode V_k diagonals
    vector<vector<Plaintext>> V_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    cout << "\nEncoding V_K_diagonals...";
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(V_k_diagonals[i - 1][j], scale, V_k_diagonals_plain[i - 1][j]);
        }
    }
    cout << "Done" << endl;

    // Encode W_k
    vector<vector<Plaintext>> W_k_diagonals_plain(dimension - 1, vector<Plaintext>(dimensionSq));
    cout << "\nEncoding W_k_diagonals...";
    for (int i = 1; i < dimension; i++)
    {
        for (int j = 0; j < dimensionSq; j++)
        {
            ckks_encoder.encode(W_k_diagonals[i - 1][j], scale, W_k_diagonals_plain[i - 1][j]);
        }
    }
    cout << "Done" << endl;

    // Encode Matrices
    // Encode Matrix 1
    vector<Plaintext> plain_matrix1_set1(dimension);
    cout << "\nEncoding Matrix 1...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix1_set1[i], scale, plain_matrix1_set1[i]);
    }
    cout << "Done" << endl;

    // Encode Matrix 2
    vector<Plaintext> plain_matrix2_set1(dimension);
    cout << "\nEncoding Matrix 2...";
    for (int i = 0; i < dimension; i++)
    {
        ckks_encoder.encode(pod_matrix2_set1[i], scale, plain_matrix2_set1[i]);
    }
    cout << "Done" << endl;

    // --------------- ENCRYPTING ----------------
    // Encrypt Matrix 1
    vector<Ciphertext> cipher_matrix1_set1(dimension);
    cout << "\nEncrypting Matrix 1...";

    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix1_set1[i], cipher_matrix1_set1[i]);
    }
    cout << "Done" << endl;

    // Encrypt Matrix 2
    vector<Ciphertext> cipher_matrix2_set1(dimension);
    cout << "\nEncrypting Matrix 2...";
    for (int i = 0; i < dimension; i++)
    {
        encryptor.encrypt(plain_matrix2_set1[i], cipher_matrix2_set1[i]);
    }
    cout << "Done" << endl;

    // --------------- MATRIX ENCODING ----------------
    // Matrix Encode Matrix 1
    cout << "\nMatrix Encoding Matrix 1...";
    Ciphertext cipher_encoded_matrix1_set1 = C_Matrix_Encode(cipher_matrix1_set1, gal_keys, evaluator);
    cout << "Done" << endl;

    // Matrix Encode Matrix 2
    cout << "\nMatrix Encoding Matrix 2...";
    Ciphertext cipher_encoded_matrix2_set1 = C_Matrix_Encode(cipher_matrix2_set1, gal_keys, evaluator);
    cout << "Done" << endl;

    /*
    // Test Matrix Encoding
    Plaintext test_matrix_encoding;
    decryptor.decrypt(cipher_encoded_matrix1_set1, test_matrix_encoding);
    vector<double> test_matrix_encoding_result(dimensionSq);
    ckks_encoder.decode(test_matrix_encoding, test_matrix_encoding_result);
    cout << "Decoded Matrix : " << endl;
    cout << "\t[";
    for (int i = 0; i < dimensionSq - 1; i++)
    {
        cout << test_matrix_encoding_result[i] << ", ";
    }
    cout << test_matrix_encoding_result[dimensionSq - 1] << "]" << endl;
*/
/*    // --------------- MATRIX MULTIPLICATION ----------------
    cout << "\nMatrix Multiplication...";
    cout << "test " << endl;
    Ciphertext ct_result = CC_Matrix_Multiplication(cipher_encoded_matrix1_set1, cipher_encoded_matrix2_set1, dimension, U_sigma_diagonals_plain, U_tau_diagonals_plain, V_k_diagonals_plain, W_k_diagonals_plain, gal_keys, params);
    cout << "Done" << endl;
}
*/
void Server::Add(SEALContext context, Ciphertext cipher1, Ciphertext cipher2, Ciphertext & destination) {

    Evaluator evaluator(context);
    cout << "Evaluator add..." << endl;
    cout << to_string(cipher1.size()) << endl;
    cout << to_string(cipher2.size()) << endl;
    evaluator.add(cipher1, cipher2, destination);
    evaluator.transform_to_ntt_inplace(destination);
}

Ciphertext Server::Multiply(SEALContext context, Ciphertext cipher1, Ciphertext cipher2) {

    Evaluator evaluator(context);
    KeyGenerator keygen(context);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);


    Ciphertext result;
    evaluator.multiply(cipher1, cipher2, result);
    evaluator.relinearize_inplace(result, relin_keys);
    return result;
}


    //destination.parms_id() = cipher.parms_id();
    //destination.scale() = encrypted.scale();
    // then add them up
