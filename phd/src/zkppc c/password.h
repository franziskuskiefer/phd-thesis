//
//  password.h
//  ZKPPC
//
//  Created by Changyu Dong on 19/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//

#ifndef ZKPPC_PASSWORD_H
#define ZKPPC_PASSWORD_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#define shiftBase 100000

typedef struct alphabet{
    BIGNUM** digit;
    BIGNUM** lower;
    BIGNUM** symbol;
    BIGNUM** upper;
    BIGNUM** whole;
    int dSize;
    int lSize;
    int sSize;
    int uSize;
    int wholeSize;
    int nmax;
}alphabet;

typedef struct pHashParam{
    //order of group
    BIGNUM* p;
    //generator
    EC_POINT* g;
    EC_POINT* h;
    EC_GROUP* curve;
    
    //security parameter
    int lamda;
}pHashParam;

typedef struct hashVal{
    EC_POINT* H1;
    EC_POINT* H2;
}hashVal;

//character to int


//build alphabet on the server side
alphabet* buildAlphabet(int nMax);

void printAlphabet(alphabet* al);

//position-dependent character mapping
BIGNUM* CHRtoINTI(char c, int i);

//mapping a password to an integer
BIGNUM* PWDtoINT(char* pwd, int pwdLen);

//password hashing setup
pHashParam* PSetup(int lambda);

//salt genration
BIGNUM* PSalt(pHashParam* param);

//pre hash
EC_POINT* PPrehash(pHashParam* param, BIGNUM* pi, BIGNUM* salt);

hashVal* PHash(pHashParam* param, EC_POINT* preHash, BIGNUM* sp,BIGNUM* sh);


//commitment
EC_POINT* commit(pHashParam* param, BIGNUM* x, BIGNUM* r);

//open
//return 1 if Com= commit(x,r), else 0;
int open(pHashParam* param, EC_POINT* Com, BIGNUM* x, BIGNUM* r);

//membership proof, return 1 is accept, 0 is not
int PoM(pHashParam* param, char* password, char* policy,BIGNUM** r,BIGNUM** pi, EC_POINT** C, alphabet* alpha);

int PoE(pHashParam* param, hashVal* H, EC_POINT* com, BIGNUM* sumPi, BIGNUM* sumR, BIGNUM* sp, BIGNUM* sh);

#endif /* ZKPPC_PASSWORD_H */
