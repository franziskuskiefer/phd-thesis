//
//  main.c
//  PSI
//
//  Created by Changyu Dong on 24/02/2013.
//  Copyright (c) 2013 Changyu Dong. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <sys/types.h>

#include "BF.h"
#include "RangeHash.h"
#include "AESRandom.h"
#include "Util.h"
#include "GarbledBF.h"
#include "RandomSource.h"
#include "MessageDigest.h"

#include "Policy.h"
#include "Shamir.h"
#include "regProtocol.h"



void testProtocol();

int main(int argc, const char *argv[])
{
    testProtocol();
}

void testProtocol(){
    //security parameter
    int security=80;
    //RSA key generation
    BN_CTX* ctx= BN_CTX_new();
    BIGNUM* P=BN_new();
    BIGNUM* Q=BN_new();
    BIGNUM* e=BN_new();
    BIGNUM* d=BN_new();
    BIGNUM* N=BN_new();
    BIGNUM* phiN=BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    
    BN_generate_prime(P, 512, 0, NULL, NULL, NULL, NULL);
    BN_generate_prime(Q, 512, 0, NULL, NULL, NULL, NULL);
    BN_generate_prime(e, 512, 0, NULL, NULL, NULL, NULL);
    
    BN_mul(N, P, Q, ctx);
    BN_sub(P, P, one);
    BN_sub(Q, Q, one);
    BN_mul(phiN,P, Q, ctx);
    BN_mod_inverse(d, e, phiN, ctx);
    
    RSAPK* pk=calloc(1, sizeof(RSAPK));
    RSASK* sk=calloc(1, sizeof(RSASK));
    
    pk->e=e;
    pk->N=N;
    
    sk->d=d;
    sk->N=N;
    
    struct timeval t1;
    struct timeval t2;
    double cpu_time_used;
    
    
    // create server
    
    char* polStr="4:(D,2)(U,2)(L,2)(S,2)";
    // Pl35B@dm1nt()n.ILuv2Pl35B@dm1nt()n.
    char* passstr="ILuv21()n.ILuv21()n.ILuv21()n.ILuv21()n.";
    printf("policy: %s\n",polStr);
    int len=strlen(polStr);
    
    server* svr;
    
    createServer(security, polStr, len, &svr);
    
    
    //create client
    //char* passstr="ILuv2PlayB@dm1nt()n.Mi$un'sBrthd8iz12124";
    
    printf("passsword length: %zd\n",strlen(passstr));
    len=strlen(passstr);
    
    client* cln;
    
    createClient(svr->p, svr->xs, svr->pol, passstr, len, &cln);
    
    BIGNUM** out;
    int outLen;
    
    //client's move prepare ui's
    
    gettimeofday(&t1, NULL);
    
    outLen= prepareuis(cln, pk, &out);
    
    
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("Client prepare uis (ms) = %f\n",cpu_time_used);
    
    
    //server's move u_i'=u_i^d
    gettimeofday(&t1, NULL);
    for(int i=0;i<outLen;i++){
        //printf("%s\n",BN_bn2hex(out[i]));
        
        BN_mod_exp(out[i], out[i], sk->d, N, ctx);
    }
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("Sever computes ui' (ms) = %f\n",cpu_time_used);
    
    //client's move again, prepare \hat{S}
    gettimeofday(&t1, NULL);
    minimalSatisfiableSet(cln->pas, cln->pol, &(cln->setC));
    
    prepareHatC(cln, pk);
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("Client prepare hat{C} (ms) = %f\n",cpu_time_used);
    
    //server's move prepare \hat{S}
    gettimeofday(&t1, NULL);
    prepareHatS(svr, sk);
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("Server prepare hat{S} (ms) = %f\n",cpu_time_used);
    
    //    //test hat sets
    //    for(int i=0;i<cln->hatCsize;i++){
    //        printBytes(cln->hatC[i], cln->MD->digestLen);
    //        int found=0;
    //        for(int j=0;j<svr->hatSsize;j++){
    //            if(compareByteArray(cln->hatC[i], svr->hatS[j], cln->MD->digestLen)){
    //                printBytes(svr->hatS[j], cln->MD->digestLen);
    //                found=1;
    //                break;
    //            }
    //        }
    //        if(found==1){
    //            printf("Found in hatS\n");
    //        }else{
    //            printf("Not in hatS\n");
    //        }
    //    }
    
    //server build GBF
    
    BFParameters* bfParam;
    
    BF_GenerateParameters(&bfParam, svr->hatSsize, security);
    AESRandom* rnd;
    AESRandom_Create(&rnd,security/8);
    RangeHash** rHashes=calloc(security, sizeof(RangeHash*));
    
    char** keys= calloc(security, sizeof(char*));
    
    for(int i=0;i<security;i++){
        keys[i]=calloc(security/8, sizeof(char));
        AESRandom_NextBytes(rnd, keys[i], security/8);
        RangeHash_Create(&rHashes[i], keys[i], security/8, bfParam->m);
    }
    
    
    //generate and send GBF
    gettimeofday(&t1, NULL);
    GarbledBF* gbf;
    
    GBF_Create(&gbf, bfParam->m, bfParam->k);
    
    for(int i=0;i<svr->hatSsize;i++){
        GBF_add(gbf, rHashes, security, svr->hatS[i], svr->MD->digestLen, svr->share[i], rnd);
    }
    
    GBF_doFinal(gbf, rnd);
    
    //client query
    
    char** shares = calloc(cln->hatCsize, sizeof(char*));
    
    for(int i=0;i<cln->hatCsize;i++){
        shares[i]=calloc(GBFSigmaByteLen, sizeof(char));
        GBF_query_get_data(gbf, rHashes, security, cln->hatC[i], cln->MD->digestLen, shares[i]);
    }
    
    //    gettimeofday(&t2, NULL);
    //    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    //    printf("OBI (ms) = %f\n",cpu_time_used);
    //
    //
    //    gettimeofday(&t1, NULL);
    
    
    //reconstruct the secrets
    BIGNUM** secrets=calloc(5, sizeof(BIGNUM*));
    
    char** start=shares;
    
    
    if(cln->setC->digitSet.size!=0){
        secrets[1]=BN_new();
        recoverSecret(cln->p, &cln->setC->digitSet,start,secrets[1]);
        start+=cln->setC->digitSet.size;
        //printf("%s\n",BN_bn2hex(secrets[1]));
        //printPolynomial(svr->polySet->digPoly);
    }
    
    
    
    if(cln->setC->lowerCaseSet.size!=0){
        secrets[2]=BN_new();
        recoverSecret(cln->p, &cln->setC->lowerCaseSet,start,secrets[2]);
        start+=cln->setC->lowerCaseSet.size;
        //printf("%s\n",BN_bn2hex(secrets[2]));
        //printPolynomial(svr->polySet->lowPoly);
    }
    
    if(cln->setC->symbolSet.size!=0){
        secrets[3]=BN_new();
        recoverSecret(cln->p, &cln->setC->symbolSet,start,secrets[3]);
        start+=cln->setC->symbolSet.size;
        //printf("%s\n",BN_bn2hex(secrets[3]));
        //printPolynomial(svr->polySet->symPolyl);
    }
    
    if(cln->setC->upperCaseSet.size!=0){
        secrets[4]=BN_new();
        recoverSecret(cln->p, &cln->setC->upperCaseSet,start,secrets[4]);
        //printf("%s\n",BN_bn2hex(secrets[4]));
        //printPolynomial(svr->polySet->upPoly);
    }
    
    BIGNUM* finalSecret=BN_new();
    BN_zero(finalSecret);
    
    if(cln->pol->topIsThresh==0){
        for(int i=1;i<5;i++){
            if(secrets[i]!=NULL){
                BN_mod_add(finalSecret, finalSecret, secrets[i], cln->p, ctx);
            }
        }
        printf("%s\n",BN_bn2hex(finalSecret));
        printPolynomial(svr->polySet->lv1Poly);
        
    }else{
        BIGNUM*** point =calloc(cln->pol->topIsThresh, sizeof(BIGNUM**));
        BIGNUM*** start=point;
        
        for(int i=1;i<5;i++){
            if(secrets[i]!=NULL){
                start[0]=calloc(2, sizeof(BIGNUM*));
                start[0][0]=svr->xs[i][1];
                start[0][1]=secrets[i];
                start++;
            }
        }
        
        reconstruct(point, cln->p, cln->pol->topIsThresh, finalSecret);
        
    }
    
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("SCP time (ms) = %f\n",cpu_time_used);
    
    //print the secret
    printf("%s\n",BN_bn2hex(finalSecret));
    //the first coefficient in the polynomial should be equal to the secret
    printPolynomial(svr->polySet->lv1Poly);
    
    
    
    //    //test shares
    //
    //    for(int i=0;i<cln->hatCsize;i++){
    //        printBytes(shares[i],GBFSigmaByteLen);
    //        int found =0;
    //        for(int j=0;j<svr->hatSsize;j++){
    //            if(compareByteArray(shares[i], svr->share[j], GBFSigmaByteLen)){
    //                printBytes(svr->share[j],GBFSigmaByteLen);
    //                found=1;
    //                break;
    //            }
    //        }
    //        if(found==1){
    //            printf("Found in share\n");
    //        }else{
    //           printf("Not in share\n"); 
    //        }
    //    }

}
