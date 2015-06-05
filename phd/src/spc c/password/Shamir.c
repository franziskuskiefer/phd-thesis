//
//  Shamir.c
//  PSI
//
//  Created by Changyu Dong on 11/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//

#include <stdio.h>
#include "Shamir.h"

void createRandomPoly(int degree,BIGNUM* p, Polynomial** result){
    Polynomial* poly=calloc(1, sizeof(Polynomial));
    
    poly->degree=degree;
    
    poly->coefficents=calloc(degree+1, sizeof(BIGNUM*));
    
    for(int i=0;i<=degree;i++){
        poly->coefficents[i]=BN_new();
        BN_rand_range(poly->coefficents[i], p);
        //printf("coefficient %d %s\n",i,BN_bn2hex(poly->coefficents[i]));
    }
    *result=poly;
}


void shareGen(Polynomial* poly, BIGNUM** xs, BIGNUM* p, BIGNUM* share){
    BN_CTX* context = BN_CTX_new();
    
    BN_zero(share);
    
    BIGNUM* temp =BN_new();
    
    for(int i=0;i<=poly->degree;i++){
        //printf("coefficient %d %s\n",i,BN_bn2hex(poly->coefficents[i]));
        //printf("xs %s\n",BN_bn2hex(xs[i]));
        //printf("p %s\n",BN_bn2hex(p));
        BN_mod_mul(temp, poly->coefficents[i], xs[i], p, context);
        BN_mod_add(share, share, temp, p,context);
    }
    

}

//ith iteration of interpolation
void iteration(BIGNUM*** points, BIGNUM* p, BN_CTX* context,int t, int i, BIGNUM* result){
    //for 0<=j<t and j!=i, multiply x_j
    //if t-1 is even do nothing, otherwise negate the product (p - the product)
    BIGNUM* up=BN_new();
    BN_one(up);
    
    for(int j=0;j<t;j++){
        if(j!=i){
            BN_mod_mul(up, up, points[j][0], p, context);
        }
        
    }
    if((t-1%2)!=0){
        BN_sub(up, p, up);
    }
    
    //lower part for 0<=j<t and j!=i, multiply x_i-x_j
    BIGNUM* xi= points[i][0];
    BIGNUM* sub= BN_new();
    BIGNUM* lower= BN_new();
    BN_one(lower);
    
    for(int j=0;j<t;j++){
        if(j!=i){
            BN_mod_sub(sub, xi, points[j][0], p, context);
            BN_mod_mul(lower, lower, sub, p, context);
        }
    }
    
    //inverse the lower part
    //up*lower^-1*y_i
    BN_mod_inverse(result, lower, p, context);
    BN_mod_mul(result, result, up, p, context);
    BN_mod_mul(result, result, points[i][1], p, context);
    
}

void reconstruct(BIGNUM*** points, BIGNUM* p, int t, BIGNUM* secret){
    BN_CTX* context = BN_CTX_new();
    
    BN_zero(secret);
    
    BIGNUM* result=BN_new();
    
    for(int i=0;i<t;i++){
        iteration(points, p, context,t, i, result);
        BN_mod_add(secret, secret, result, p, context);
    }
    
}

void printPolynomial(Polynomial* p){
    if (p==NULL) {
        printf("[]\n");
        return;
    }
    printf("[");
    for(int i=0;i<p->degree;i++){
        printf("%s ",BN_bn2hex(p->coefficents[i]));
    }
    printf("%s]\n",BN_bn2hex(p->coefficents[p->degree]));
}

