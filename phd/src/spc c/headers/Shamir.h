//
//  Shamir.h
//  PSI
//
//  Created by Changyu Dong on 11/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//

//shamir secret sharing


#ifndef PSI_Shamir_h
#define PSI_Shamir_h
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>


typedef struct Polynomial{
    BIGNUM** coefficents;
    int degree;
}Polynomial;

void printPolynomial(Polynomial* p);


//create a random polynomial over Zp of the given degree
void createRandomPoly(int degree,BIGNUM* p, Polynomial** result);

//use a polynomial to generate shares, a_0 is the secret
//xs contains x^0,x^1,...,x^degree.
//to generate a share for a character, use its xs to evaluate the polynomial
//the result is the share.
void shareGen(Polynomial* poly, BIGNUM** xs, BIGNUM* p, BIGNUM* share);

//points are (x,y) pairs
//t is the threshold also how many points are supplied
//secret is the secret recustructed from the points
void reconstruct(BIGNUM*** points, BIGNUM* p, int t, BIGNUM* secret);



#endif
