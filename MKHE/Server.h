//
// Created by avacado on 2020/11/30.
//

#include "seal/seal.h"

using namespace std;
using namespace seal;

class Server {
private:
    int numberOfUsers;
    double scale;
    vector<PublicKey>  PublicKeys;
    Ciphertext CC_MatrixMultiplication(Ciphertext, Ciphertext, SEALContext, int);
    Ciphertext MatrixMultiplication(Ciphertext, Ciphertext, SEALContext, int);
public:
    /*
     * Parameter of Server constructor:
     * scale: double
     */
    Server(int, double);

    /*
     * Perform addition
     */
    void Add(SEALContext, Ciphertext, Ciphertext, Ciphertext&);

    /*
     * Perform multiplication
     */
    Ciphertext Multiply(SEALContext, Ciphertext, Ciphertext);

};


