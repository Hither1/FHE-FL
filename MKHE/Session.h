//
// Created by avacado on 2020/11/21.
// Represent a training session
//


#include "PublicParameter.h"
#include "User.h"
#include "ModelProvider.h"
#include "Server.h"
#include <set>

class Session {
private:
    int SecurityParameter = 128; // Set the default lambda to be 128
    int numberOfUsers;
    vector<User> SessionUsers;
public:
    Session(int);
    void setSecurityParameter(int);
    void Start();
    void preprocessing(SEALContext, Ciphertext &, set<int> &, Ciphertext &, set<int> &);
};


