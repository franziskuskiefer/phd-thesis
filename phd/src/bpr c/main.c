//
//  main.c
//  BPR
//
//  Created by Changyu Dong on 19/03/2015.
//  Copyright (c) 2015 Changyu Dong, Franziskus Kiefer. All rights reserved.
//

#include <stdio.h>
#include "password.h"
#include <sys/time.h>

int main(int argc, const char * argv[])
{
    struct timeval t1;
    struct timeval t2;
    double cpu_time_used;
    
    struct timeval t3;
    struct timeval t4;
    int secLv=80;
    
    char* policy="duls";
    char* password="Iu1(";
    
    pHashParam* param= PSetup(secLv);
    
    // build the alphabet
    // size is fixed to 1 in BPR (no upper bound for passwords)
    alphabet* alpha= buildAlphabet(1);
    
    int n = strlen(password);
    
    BN_CTX* ctx=BN_CTX_new();
    //********************client's move
    //map each character & shuffle
    BIGNUM** pi = calloc(n, sizeof(BIGNUM*));
    BIGNUM** pip = calloc(n, sizeof(BIGNUM*));
    BIGNUM** r = calloc(n, sizeof(BIGNUM*));
    BIGNUM** rp = calloc(n, sizeof(BIGNUM*));
    EC_POINT** C = calloc(n, sizeof(EC_POINT*));
    EC_POINT** Cp = calloc(n, sizeof(EC_POINT*));
    
    gettimeofday(&t1, NULL);
    
    //generate commitments
    for(int i=0;i<n;i++){
        //char to int value
        pi[i] = CHRtoINTI(password[i], 0); //XXX CHRtoInt2
        
        //random number, secret for commitment
        r[i]=PSalt(param);
        
        //second random number for re-commitment
        rp[i]=PSalt(param);
        
        //commitments of (pi[i],r[i])
        C[i]=commit(param, pi[i], r[i]);
        
        //re-commitments of (pi[i],r[i]+rp[i])
        BIGNUM* rs = BN_new();
        BN_mod_add(rs, r[i], rp[i], param->p, ctx);
        Cp[i]=commit(param, pi[i], rs);
    }
    
    // shuffle pi
    int* k = calloc(n, sizeof(int));
    shuffle(pi, pip, k, n);
/*    for(int i=0; i < n; i++){*/
/*        printf("k: %d\n",k[i]);*/
/*        printf("pi: %s\n",BN_bn2dec(pi[i]));*/
/*        printf("pip: %s\n",BN_bn2dec(pip[i]));*/
/*    }*/
    
    BIGNUM* sumPi = BN_new();
    BIGNUM* sumRi = BN_new();
    EC_POINT* sumCi = EC_POINT_new(param->curve);
    
    BN_copy(sumPi, pi[0]);
    BN_copy(sumRi, r[0]);
    EC_POINT_copy(sumCi, C[0]);
    
    for(int i=1;i<n;i++){
        BN_mod_add(sumPi, sumPi, pi[i], param->p, ctx);
        BN_mod_add(sumRi, sumRi, r[i], param->p, ctx);
        EC_POINT_add(param->curve, sumCi, sumCi, C[i], ctx);
    }
    
    //hash
    BIGNUM* sp = PSalt(param);
    BIGNUM* sh = PSalt(param);
    
    EC_POINT* preHash= PPrehash(param, sumPi, sp);
    hashVal* H=PHash(param, preHash, sp, sh);
    
    //server's move
    //compute sumCi
    EC_POINT* sumCI_S= EC_POINT_new(param->curve);
    EC_POINT_copy(sumCI_S, C[0]);
    
    for(int i=1;i<n;i++){
        EC_POINT_add(param->curve, sumCI_S, sumCI_S, C[i], ctx);
    }
    
    //membership proof
    
    gettimeofday(&t3, NULL);
    int accept = PoM(param,password, policy, r, pi, C, alpha);
    
    gettimeofday(&t4, NULL);
    cpu_time_used = (double)(t4.tv_sec-t3.tv_sec)*1000+(double)(t4.tv_usec-t3.tv_usec)/1000;
    printf("PoM time (ms) = %f\n",cpu_time_used);
    
    if(accept==1){
        //printf("PoM succeeded\n");
    }else{
        printf("PoM failed\n");
    }

    
    accept=PoE(param, H, sumCI_S, sumPi, sumRi, sp, sh);
    
    if(accept==1){
       // printf("PoE succeeded\n");
    }else{
        printf("PoE failed\n");
    }

    
    
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("Total time (ms) = %f\n",cpu_time_used);
    

   
    exit(0);


}

