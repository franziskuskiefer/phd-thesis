//
//  password.h
//  BPR
//
//  Created by Changyu Dong on 19/03/2015.
//  Copyright (c) 2015 Changyu Dong, Franziskus Kiefer. All rights reserved.
//

#ifndef BPR_PASSWORD_H
#define BPR_PASSWORD_H

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

// mapping a character to an integer BIGNUM
BIGNUM* CHRtoINT2(char c);

//position-dependent character mapping
BIGNUM* CHRtoINTI(char c, int i);

//mapping a password to an integer
BIGNUM* PWDtoINT(char* pwd, int pwdLen);

//password hashing setup
pHashParam* PSetup(int lambda);

//salt genration
BIGNUM* PSalt(pHashParam* param);

// shuffle array of integers
void shuffle(BIGNUM** pi, BIGNUM** pip, int* k, int n);

//pre hash
EC_POINT* PPrehash(pHashParam* param, BIGNUM* pi, BIGNUM* salt);

hashVal* PHash(pHashParam* param, EC_POINT* preHash, BIGNUM* sp,BIGNUM* sh);


//commitment
EC_POINT* commit(pHashParam* param, BIGNUM* x, BIGNUM* r);

//membership proof, return 1 is accept, 0 is not
int PoM(pHashParam* param, char* password, char* policy,BIGNUM** r,BIGNUM** pi, EC_POINT** C, alphabet* alpha);

int PoE(pHashParam* param, hashVal* H, EC_POINT* com, BIGNUM* sumPi, BIGNUM* sumR, BIGNUM* sp, BIGNUM* sh);

#endif /* BPR_PASSWORD_H */
