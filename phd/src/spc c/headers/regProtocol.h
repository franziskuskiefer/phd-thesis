//
//  regProtocol.h
//  PSI
//
//  Created by Changyu Dong on 16/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//

#ifndef PSI_regProtocol_h
#define PSI_regProtocol_h
#include "Policy.h"
#include "Shamir.h"
#include "MessageDigest.h"
#define shareByteSize 10

typedef struct RSAPK{
    BIGNUM* N;
    BIGNUM* e;
}RSAPK;

typedef struct RSASK{
    BIGNUM* N;
    BIGNUM* d;
}RSASK;

typedef  struct polynomialSet{
    Polynomial* lv1Poly;
    Polynomial* digPoly;
    Polynomial* lowPoly;
    Polynomial* upPoly;
    Polynomial* symPolyl
}polynomialSet;

void printPolynomialSet(polynomialSet* pset);

typedef struct server{
    //field modulus for secret sharing
    BIGNUM* p;
    //x values for secret shares
    BIGNUM*** xs;
    
    //policy
    Policy* pol;
    
    //polynomials for secret sharing
    polynomialSet* polySet;
    
    //server's set
    minimalSet* setS;
    
    MessageDigest* MD;
    
    char** hatS;
    char** share;
    int hatSsize;
    
}server;

typedef struct client{
    BIGNUM* p;
    Policy* pol;
    Password* pas;
    //hash of password string
    char* passhash;
    minimalSet* setC;
    MessageDigest* MD;
    
    char** hatC;
    int hatCsize;
}client;

void createServer(int pSize, char* policy,int polLength, server** s);

void createClient(BIGNUM* p, BIGNUM*** xs,Policy* policy,char* password, int passLen,client** c);

//return an array of u_i, array length is returned.
int prepareuis(client* c, RSAPK* pk, BIGNUM*** result);

void prepareHatC(client*c,RSAPK*pk );

void prepareHatS(server* s,RSASK* sk );

void recoverSecret(BIGNUM* p, charSet* set,char** shares,BIGNUM* secret);

#endif
