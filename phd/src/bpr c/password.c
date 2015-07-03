//
//  password.c
//  BPR
//
//  Created by Changyu Dong on 19/03/2015.
//  Copyright (c) 2015 Changyu Dong, Franziskus Kiefer. All rights reserved.
//

#include <stdio.h>
#include "password.h"
#include <stdbool.h>
#include <arpa/inet.h>   // For htonl to make the integer big endian

void printPoint(EC_POINT* P, pHashParam* param) {
	printPoint2("P: ", P, param);
}

void printPoint2(char* s, EC_POINT* P, pHashParam* param) {
	BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  if (EC_POINT_get_affine_coordinates_GFp(param->curve, P, x, y, NULL)) {
		printf("%s (%s, %s)\n", s, BN_bn2dec(x), BN_bn2dec(y));
  }
}

int CHRtoInt(char c){
    assert(c>=33 &&c<=126);
    return c-32;
}

BIGNUM* CHRtoInt2(char c){
    assert(c>=33 &&c<=126);
    
    BIGNUM* bn = BN_new();
    BN_set_word(bn, CHRtoInt(c));
    
    return bn;
}

int isLowerCase(char ch){
    return ch>=97&&ch<=122;
}

int isUpperCase(char ch){
    return ch>=65&&ch<=90;
}

int isDigit(char ch){
    return ch>=48&&ch<=57;
}

int isSymbol(char ch){
    return (ch>=33&&ch<=47)||(ch>=58&&ch<=64)||(ch>=91&&ch<=96)||(ch>=123&&ch<=126);
}

BIGNUM* CHRtoINTI(char c, int i){
    BIGNUM* bn=BN_new();
    BN_set_word(bn, shiftBase);
    BIGNUM* temp = BN_new();
    BN_set_word(temp, i);
    
    BN_CTX* ctx=BN_CTX_new();
    BN_exp(bn, bn, temp, ctx);
    BN_set_word(temp, CHRtoInt(c));
    BN_mul(bn, bn, temp, ctx);
    
    BN_free(temp);
    BN_CTX_free(ctx);
    
    return bn;
}


BIGNUM* PWDtoINT(char* pwd, int pwdLen){
    BIGNUM* result=BN_new();
    BN_CTX* ctx= BN_CTX_new();
    BN_zero(result);
    
    for(int i=0;i<pwdLen;i++){
        BIGNUM* temp=CHRtoINTI(pwd[i], i);
        BN_add(result, result, temp);
        BN_free(temp);
    }
    
    BN_CTX_free(ctx);
    
    return result;
}

pHashParam* PSetup(int secLev){
    assert(secLev==80||secLev==128||secLev==192||secLev==256);
    
    pHashParam* result= calloc(1, sizeof(pHashParam));
    result->lamda=secLev;
    
    if(secLev==80){
        result->curve=EC_GROUP_new_by_curve_name(NID_X9_62_prime192v1);
    
    }else if(secLev==128){
        result->curve=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        
    }else if(secLev==192){
        result->curve=EC_GROUP_new_by_curve_name(NID_secp384r1);
        
    }else if(secLev==256){
        result->curve=EC_GROUP_new_by_curve_name(NID_secp521r1);
        
    }
    
    //order
    result->p= BN_new();
    BN_CTX* ctx=BN_CTX_new();
    EC_GROUP_get_order(result->curve, result->p, ctx);
    
    //generator
    result->g = EC_POINT_dup(EC_GROUP_get0_generator(result->curve), result->curve);
    
    // h
    BIGNUM* rnd = BN_new();
    BN_rand_range(rnd, result->p);
/*    BN_one(rnd);*/
    result->h = EC_POINT_new(result->curve);
    EC_POINT_mul(result->curve, result->h, NULL, result->g, rnd, ctx);
    
    // generate f (100)
    result->f = calloc(100, sizeof(EC_POINT*));
    for (int i = 0; i < 100; ++i) {
		  BN_rand_range(rnd, result->p);
/*	    BN_one(rnd);*/
		  result->f[i] = EC_POINT_new(result->curve);
		  EC_POINT_mul(result->curve, result->f[i], NULL, result->g, rnd, ctx);
    }
    
    BN_free(rnd);
    BN_CTX_free(ctx);
    return result;
}

BIGNUM* PSalt(pHashParam* param){
    BIGNUM* salt=BN_new();

// FIXME    
    BN_rand_range(salt, param->p);
/*		BN_one(salt);*/
    return salt;
    
}

EC_POINT* PPrehash(pHashParam* param, BIGNUM* pi, BIGNUM* salt){
    BIGNUM* temp=BN_new();
    BN_CTX* ctx=BN_CTX_new();
    
    BN_mod_mul(temp, pi, salt, param->p, ctx);
    
    EC_POINT* result= EC_POINT_new(param->curve);
    
    EC_POINT_mul(param->curve, result, NULL, param->g, temp, ctx);
    
    BN_free(temp);
    BN_CTX_free(ctx);
    
    return result;
}

hashVal* PHash(pHashParam* param, EC_POINT* preHash, BIGNUM* sp,BIGNUM* sh){
    BN_CTX* ctx=BN_CTX_new();
    hashVal* H = calloc(1, sizeof(hashVal));
    
    H->H1=EC_POINT_new(param->curve);
    H->H2=EC_POINT_new(param->curve);
    
    EC_POINT_mul(param->curve, H->H1, NULL, param->g, sp, ctx);
    
    EC_POINT_mul(param->curve, H->H2, NULL, param->h, sh, ctx);
    
    EC_POINT_add(param->curve, H->H2, H->H2, preHash, ctx);
    
    return H;
}

EC_POINT* commit(pHashParam* param, BIGNUM* x, BIGNUM* r){
    EC_POINT* result=EC_POINT_new(param->curve);
    EC_POINT* temp= EC_POINT_new(param->curve);
    BN_CTX* ctx=BN_CTX_new();
    
    EC_POINT_mul(param->curve, result, NULL, param->g, x, ctx);
    EC_POINT_mul(param->curve, temp, NULL, param->h, r, ctx);
    
    EC_POINT_add(param->curve, result, result, temp, ctx);
    
    BN_CTX_free(ctx);
    EC_POINT_free(temp);
    
    return result;
}

alphabet* buildAlphabet(int nMax){
    alphabet* result= calloc(1, sizeof(alphabet));
    result->nmax=nMax;
    
    result->dSize=10*nMax;
    result->uSize=26*nMax;
    result->lSize=26*nMax;
    result->sSize=32*nMax;
    
    result->digit=calloc(result->dSize, sizeof(BIGNUM*));
    result->upper=calloc(result->uSize, sizeof(BIGNUM*));
    result->lower=calloc(result->lSize, sizeof(BIGNUM*));
    result->symbol=calloc(result->sSize, sizeof(BIGNUM*));
    
    BIGNUM** digit=result->digit;
    BIGNUM** upper=result->upper;
    BIGNUM** lower=result->lower;
    BIGNUM** symbol=result->symbol;
    
    
    for(int i=0;i<nMax;i++){
        for(char j=33;j<=126;j++){
            if(isDigit(j)){
                digit[0]=CHRtoINTI(j, i);
                digit++;
            }else if(isLowerCase(j)){
                lower[0]=CHRtoINTI(j, i);
                lower++;
            }else if(isSymbol(j)){
                symbol[0]=CHRtoINTI(j, i);
                symbol++;
            }else if(isUpperCase(j)){
                upper[0]=CHRtoINTI(j, i);
                upper++;
            }
        }
        
    }
    
    result->wholeSize=result->dSize+result->lSize+result->sSize+result->uSize;
    
    result->whole=calloc(result->wholeSize, sizeof(BIGNUM*));
    
    BIGNUM** start=result->whole;
    
    memcpy(start,result->digit,result->dSize*sizeof(BIGNUM*));
    start+=result->dSize;
    
    memcpy(start, result->lower, result->lSize*sizeof(BIGNUM*));
    start+=result->lSize;
    
    memcpy(start, result->symbol, result->sSize*sizeof(BIGNUM*));
    start+=result->sSize;
    
    memcpy(start, result->upper, result->uSize*sizeof(BIGNUM*));
    
    return result;
    
}

void printAlphabet(alphabet* al){
    printf("nmax = %d\n",al->nmax);
    
    printf("digit set size = %d\n",al->dSize);
    printf("lower case set size = %d\n",al->lSize);
    printf("symbol set size = %d\n",al->sSize);
    printf("upper case size = %d\n",al->uSize);
    printf("union size = %d\n",al->wholeSize);
    
    
    printf("digit set \n");
    for(int i=0;i<al->dSize;i++){
        printf("%s\n",BN_bn2dec(al->digit[i]));
    }
    printf("\n");
    
    printf("lower case set \n");
    for(int i=0;i<al->lSize;i++){
        printf("%s\n",BN_bn2dec(al->lower[i]));
    }
    printf("\n");
    
    printf("symbol set \n");
    for(int i=0;i<al->sSize;i++){
        printf("%s\n",BN_bn2dec(al->symbol[i]));
    }
    printf("\n");
    
    printf("upper case set \n");
    for(int i=0;i<al->uSize;i++){
        printf("%s\n",BN_bn2dec(al->upper[i]));
    }
    printf("\n");
    
    printf("all sets \n");
    for(int i=0;i<al->wholeSize;i++){
        printf("%s\n",BN_bn2dec(al->whole[i]));
    }
    printf("\n");
    
    
    
}

int findSet(char ch, alphabet* alpha, char* policy, BIGNUM*** result){
    //printf("Character %c, ",ch);
    
    //find the set which contains the character.
    if(isDigit(ch)){
        for(int i=0;i<strlen(policy);i++){
            if(policy[i]=='d'){
                policy[i]='0';
                *result=alpha->digit;
                //printf("use digit set\n");
                return alpha->dSize;
            }
        }
        *result=alpha->whole;
        //printf("use whole alphabet\n");
        return alpha->wholeSize;
    }
    
    if(isLowerCase(ch)){
        for(int i=0;i<strlen(policy);i++){
            if(policy[i]=='l'){
                policy[i]='0';
                *result=alpha->lower;
                //printf("use lower case set\n");
                return alpha->lSize;
            }
        }
        *result=alpha->whole;
        //printf("use whole alphabet\n");
        return alpha->wholeSize;
    }
    
    
    if(isSymbol(ch)){
        for(int i=0;i<strlen(policy);i++){
            if(policy[i]=='s'){
                policy[i]='0';
                *result=alpha->symbol;
                //printf("use symbol set\n");
                return alpha->sSize;
            }
        }
        *result=alpha->whole;
        //printf("use whole alphabet\n");
        return alpha->wholeSize;
    }
    
    if(isUpperCase(ch)){
        for(int i=0;i<strlen(policy);i++){
            if(policy[i]=='u'){
                policy[i]='0';
                *result=alpha->upper;
                //printf("use uppercase set\n");
                return alpha->uSize;
            }
        }
        *result=alpha->whole;
        //printf("use whole alphabet\n");
        return alpha->wholeSize;
    }
    
    return 0;
}

//ith char membership proof
//return 1 if successful
int setMembership(pHashParam* param, int position,BIGNUM** r,BIGNUM** pi, EC_POINT** C, BIGNUM** set, int setSize,BIGNUM* challenge){
    //printf("the %dth setmembership proof\n", position);
    //client's move
    BIGNUM** s= calloc(setSize, sizeof(BIGNUM*));
    BIGNUM** c= calloc(setSize, sizeof(BIGNUM*));
    EC_POINT** t= calloc(setSize, sizeof(EC_POINT*));
    BIGNUM* k=PSalt(param);
    
    BIGNUM* clx=BN_new();
    BN_zero(clx);
    BIGNUM* slx=BN_new();
    
    BN_CTX* ctx=BN_CTX_new();
    EC_POINT* temp= EC_POINT_new(param->curve);
    
    for(int j=0;j<setSize;j++){
        //the jth char in the set is euqal to the chat to be proved
        if(BN_cmp(pi[position], set[j])==0){
            c[j]=clx;
            s[j]=slx;
            //g^pi[i]h^k
            t[j]=commit(param, pi[position], k);
            
        }else{
            c[j]=PSalt(param);
            BN_mod_add(clx, clx, c[j], param->p, ctx);
            s[j]=PSalt(param);
            //g^set[j]h^s[j]
            t[j]=commit(param, set[j], s[j]);

            //g^set[j]
            EC_POINT_mul(param->curve, temp, NULL, param->g, set[j], ctx);
            //g^-set[j]
            EC_POINT_invert(param->curve, temp, ctx);
            //C/g^set[j]
            EC_POINT_add(param->curve, temp, temp, C[position], ctx);
            //(C/g^set[j])^c[j]
            EC_POINT_mul(param->curve, temp, NULL, temp, c[j], ctx);
            //g^set[j]h^s[j](C/g^set[j])^c[j]
            EC_POINT_add(param->curve, t[j], t[j], temp, ctx);
            
        }
    }
    
    //clx= c- sum c[j]
    BN_mod_sub(clx, challenge, clx, param->p, ctx);
    
    //slx=k-clx*r_i
    BN_mod_mul(slx, clx, r[position], param->p, ctx);
    BN_mod_sub(slx, k, slx, param->p, ctx);
    
    //server verify
    
    BIGNUM* sum= BN_new();
    BN_zero(sum);
    for(int j=0;j<setSize;j++){
        BN_mod_add(sum, sum, c[j], param->p, ctx);
    }
    if(BN_cmp(sum, challenge)!=0){
        printf("sum is not euqal to challenge\n");
        return 0;
    }
    
    for(int j=0;j<setSize;j++){
        EC_POINT * first= commit(param, set[j], s[j]);
        
        //g^set[j]
        EC_POINT_mul(param->curve, temp, NULL, param->g, set[j], ctx);
        //g^-set[j]
        EC_POINT_invert(param->curve, temp, ctx);
        //C/g^set[j]
        EC_POINT_add(param->curve, temp, temp, C[position], ctx);
        //(C/g^set[j])^c[j]
        EC_POINT_mul(param->curve, temp, NULL, temp, c[j], ctx);
        //g^set[j]h^s[j](C/g^set[j])^c[j]
        EC_POINT_add(param->curve, first, first, temp, ctx);
        
        if(EC_POINT_cmp(param->curve, first, t[j], ctx)!=0){
            printf("t[j] is not euqal\n");
            return 0;
        }
    }
    
    return 1;
    
}

bool isInArray(int val, int *arr, int size) {
    int i;
    for (i=0; i < size; i++) {
        if (arr[i] == val)
            return true;
    }
    return false;
}

void shuffle(void** in, void** out, int* k, int n, int random) {
		BIGNUM* range = BN_new();
    BN_set_word(range, n);
    BIGNUM* temp = BN_new();
		for(int i=0; i<n; ++i) {
				bool done = false;
				do {
						if (random) {
								BN_rand_range(temp, range);
								char* tmp = BN_bn2dec(temp);
								k[i] = atoi(tmp);
						}
						if (!isInArray(k[i], k, i) || !random) {
								done = true;
								out[i] = in[k[i]];
						}
				} while (!done);
    }
}

int PoM(pHashParam* param, int* k, char* password, char* policy, BIGNUM** r, BIGNUM** pi, EC_POINT** C, alphabet* alpha){
    //make a copy of the policy
    char* polCopy= calloc(strlen(policy)+1, sizeof(char));
    strcpy(polCopy, policy);
    int n=strlen(password);
    printf("password: %s\n",password);
    printf("policy: %s\n",policy);
    printf("password length = %d\n",n);
    
    BIGNUM* challenge = BN_new();
    BN_rand_range(challenge, param->p);
    
    //prove the ith char is in a set determined by the policy
    for(int i=0;i<n;i++){
        //find the server's set to run proof protocol
        BIGNUM** set;
        int setSize = findSet(password[k[i]], alpha, polCopy, &set);
        
        //character is not in the alphabet
        if(setSize==0){
            return 0;
        }
        
        int accept=setMembership(param, i, r, pi, C, set, setSize, challenge);
        
        if(accept==0)
            return 0;
    }
    
    return 1;
}

int PoS(pHashParam* param, int n, int* k, BIGNUM** rrp, BIGNUM** rp, BIGNUM** r, BIGNUM** pi, BIGNUM** pip, EC_POINT** C, EC_POINT** Cp) {
	
/*	printf("PoS\n");*/

  BN_CTX* ctx = BN_CTX_new();

	int m = htonl(2);
	BIGNUM* one = BN_new();
	BN_bin2bn( (unsigned char *) &m, sizeof(m), one);
  	
	m = htonl(2);
	BIGNUM* two = BN_new();
	BN_bin2bn( (unsigned char *) &m, sizeof(m), two);
	
	m = htonl(3);
	BIGNUM* three = BN_new();
	BN_bin2bn( (unsigned char *) &m, sizeof(m), three);
  
	// choose randome A'
	BIGNUM** Ap = calloc(n+5, sizeof(BIGNUM*));
	for (int i = -4; i < n+1; ++i) {
		Ap[i+4] = BN_new();
    BN_rand_range(Ap[i+4], param->p);
	}
	
	// build matrix A
	int MSize = (n+5)*(n+1);
	BIGNUM*** A = calloc(MSize, sizeof(BIGNUM*));
	for (int i = -4; i < n+1; ++i) { // choose random values, set re-randomiser and set shuffle matrix, fill the rest with 0
		A[i+4] = calloc(n+1, sizeof(BIGNUM*));
		for (int j = 0; j < n+1; ++j) {
			A[i+4][j] = BN_new();
			if (j == 0 || i == -1) {
				BN_rand_range(A[i+4][j], param->p);
			} else if (i == 0) {
				BN_copy(A[i+4][j], rp[j-1]);
			} else if (i > 0 && i-1 == k[j-1]) {
				BN_one(A[i+4][j]);
			} else {
				BN_zero(A[i+4][j]);
			}
		}
	}
	
	BIGNUM* tmp = BN_new();
	for (int j = 1; j < n+1; ++j) { // replace 0s with the correct values
		for (int v = 1; v < n+1; ++v) {
			// -4,j
			BN_mod_mul(tmp, A[v+4][0], A[v+4][j], param->p, ctx);
			BN_mod_mul(tmp, tmp, two, param->p, ctx);
			BN_mod_add(A[0][j], A[0][j], tmp, param->p, ctx);
			
			// -3,j
			BN_mod_mul(tmp, A[v+4][0], A[v+4][j], param->p, ctx);
			BN_mod_mul(tmp, tmp, three, param->p, ctx);
			BN_mod_add(A[1][j], A[1][j], tmp, param->p, ctx);
			
			// -2,j
			BN_mod_exp(tmp,  A[v+4][0], two, param->p, ctx);
			BN_mod_mul(tmp, tmp, A[v+4][j], param->p, ctx);
			BN_mod_mul(tmp, tmp, three, param->p, ctx);
			BN_mod_add(A[2][j], A[2][j], tmp, param->p, ctx);
		}
	}
	
	// compute commitment to A
	EC_POINT** fpv = calloc(MSize, sizeof(EC_POINT*));
	EC_POINT* temp = EC_POINT_new(param->curve);
	for (int v = 0; v < n+1; ++v) {
		fpv[v] = EC_POINT_new(param->curve);
		EC_POINT_mul(param->curve, fpv[v], NULL, param->f[0], A[0][v], ctx);
		for (int j = -3; j < n+1; ++j) {
			EC_POINT_mul(param->curve, temp, NULL, param->f[j+4], A[j+4][v], ctx);
			EC_POINT_add(param->curve, fpv[v], fpv[v], temp, ctx);
		}
	}
	
	EC_POINT* ftil = EC_POINT_new(param->curve);
	EC_POINT_mul(param->curve, ftil, NULL, param->f[0], Ap[0], ctx);
	for (int j = -3; j < n+1; ++j) {
		EC_POINT_mul(param->curve, temp, NULL, param->f[j+4], Ap[j+4], ctx);
		EC_POINT_add(param->curve, ftil, ftil, temp, ctx);
	}

	BIGNUM* piSum = BN_new();
	BN_mod_mul(piSum, pi[0], A[5][0], param->p, ctx);

	BIGNUM* rSum = BN_new();
	BN_mod_mul(rSum, r[0], A[5][0], param->p, ctx);	
  BN_mod_add(rSum, A[4][0], rSum, param->p, ctx);
	for (int j = 1; j < n; ++j) { // in range(1, len(pwd)):
		BN_mod_mul(tmp, pi[j], A[j+5][0], param->p, ctx);	
		BN_mod_add(piSum, piSum, tmp, param->p, ctx);		
		
		BN_mod_mul(tmp, r[j], A[j+5][0], param->p, ctx);	
		BN_mod_add(rSum, rSum, tmp, param->p, ctx);
	}
	EC_POINT* Cp0 = EC_POINT_new(param->curve);
	EC_POINT_mul(param->curve, Cp0, NULL, param->g, piSum, ctx);
	EC_POINT_mul(param->curve, temp, NULL, param->h, rSum, ctx);
	EC_POINT_add(param->curve, Cp0, Cp0, temp, ctx);

	BIGNUM* w = BN_new();
	BN_zero(w);
	BN_mod_sub(w, w, A[2][0], param->p, ctx);
	BN_mod_sub(w, w, Ap[1], param->p, ctx);

	BIGNUM* wtil = BN_new();
	BN_zero(wtil);
	BN_mod_sub(wtil, wtil, A[0][0], param->p, ctx);
	
	for (int j = 0; j < n; ++j) {
		BN_mod_exp(tmp,  A[j+5][0], three, param->p, ctx);
		BN_mod_add(w, w, tmp, param->p, ctx);
		
		BN_mod_exp(tmp, A[j+5][0], two, param->p, ctx);
		BN_mod_add(wtil, wtil, tmp, param->p, ctx);	
	}
	
	// GENERATE PoS CHALLENGES
	BIGNUM** challenges = calloc(n+1, sizeof(BIGNUM*));
	challenges[0] = BN_new();
	BN_one(challenges[0]);
	for (int i = 1; i < n+1; ++i) {
		challenges[i] = BN_new();
		BN_rand_range(challenges[i], param->p);
	}
	
	// PROVE PoS
	BIGNUM** s = calloc(n+1+4, sizeof(BIGNUM*));
	BIGNUM** sp = calloc(n+1+4, sizeof(BIGNUM*));
	for (int v = -4; v < n+1; ++v) { // in range(-4, len(self.pwd)+1):
		s[v+4] = BN_new();
		sp[v+4] = BN_new();
		BN_mod_mul(s[v+4], A[v+4][0], challenges[0], param->p, ctx);
		BN_copy(sp[v+4], Ap[v+4]);
		for (int j = 1; j < n+1; ++j) { // in range(1, len(self.pwd)+1):
			BN_mod_mul(tmp, A[v+4][j], challenges[j], param->p, ctx);
			BN_mod_add(s[v+4], s[v+4], tmp, param->p, ctx);	
			
			BN_mod_exp(tmp, challenges[j], two, param->p, ctx);
			BN_mod_mul(tmp, A[v+4][j], tmp, param->p, ctx);
			BN_mod_add(sp[v+4], sp[v+4], tmp, param->p, ctx);	
		}
	}

	// VERIFY PoS
	BIGNUM* a = BN_new();
	BN_rand_range(a, param->p);

	EC_POINT* f1 = EC_POINT_new(param->curve);
	BN_mod_mul(tmp, a, sp[0], param->p, ctx);
	BN_mod_add(tmp, s[0], tmp, param->p, ctx);
	EC_POINT_mul(param->curve, f1, NULL, param->f[0], tmp, ctx);
	for	(int v = -3; v < n+1; ++v) {
		BN_mod_mul(tmp, a, sp[v+4], param->p, ctx);
		BN_mod_add(tmp, s[v+4], tmp, param->p, ctx);
		EC_POINT_mul(param->curve, temp, NULL, param->f[v+4], tmp, ctx);
		EC_POINT_add(param->curve, f1, f1, temp, ctx);		
	}
  
	EC_POINT* f2 = EC_POINT_new(param->curve); 
	EC_POINT_mul(param->curve, f2, NULL, ftil, a, ctx);		
	EC_POINT_add(param->curve, f2, fpv[0], f2, ctx); 
	for (int j = 1; j < n+1; ++j) {
		BN_mod_exp(tmp, challenges[j], two, param->p, ctx);		
		BN_mod_mul(tmp, a, tmp, param->p, ctx);
		BN_mod_add(tmp, challenges[j], tmp, param->p, ctx);
		EC_POINT_mul(param->curve, temp, NULL, fpv[j], tmp, ctx);	
		EC_POINT_add(param->curve, f2, f2, temp, ctx);		
	}
	
	if (EC_POINT_cmp(param->curve, f1, f2, ctx) != 0){
		printf(">>>>>>>>>>>>>>> f1 != f2 :(\n");
		printPoint(f1, param);
		printPoint(f2, param);
		return 0;
	}
	
	EC_POINT* cProd = EC_POINT_new(param->curve);
	EC_POINT_mul(param->curve, cProd, NULL, param->h, s[4], ctx);
	for (int v = 0; v < n; ++v) {
		EC_POINT_mul(param->curve, temp, NULL, C[v], s[v+5], ctx);
		EC_POINT_add(param->curve, cProd, cProd, temp, ctx); 
	}
  
  EC_POINT* cpProd = EC_POINT_new(param->curve);
  EC_POINT_copy(cpProd, Cp0);
	for (int j = 0; j < n; ++j) {
		EC_POINT_mul(param->curve, temp, NULL, Cp[j], challenges[j+1], ctx);
		EC_POINT_add(param->curve, cpProd, cpProd, temp, ctx); 
	}
	
	if (EC_POINT_cmp(param->curve, cProd, cpProd, ctx) != 0){
		printf(">>>>>>>>>>>>>>> cProd != cpProd :(\n");
		printPoint(cProd, param);
		printPoint(cpProd, param);
		return 0;
	}
  
	BIGNUM* l1 = BN_new();
	BIGNUM* l2 = BN_new();
	BN_zero(l1);
	BN_zero(l2);
	BIGNUM* tmp2 = BN_new();
	for (int j = 1; j < n+1; ++j) {
		BN_mod_exp(tmp, challenges[j], two, param->p, ctx);
		BN_mod_exp(tmp2, s[j+4], two, param->p, ctx);
		BN_mod_sub(tmp, tmp2, tmp, param->p, ctx);
		BN_mod_add(l2, l2, tmp, param->p, ctx);
		
		BN_mod_exp(tmp, challenges[j], three, param->p, ctx);
		BN_mod_exp(tmp2, s[j+4], three, param->p, ctx);
		BN_mod_sub(tmp, tmp2, tmp, param->p, ctx);
		BN_mod_add(l1, l1, tmp, param->p, ctx);
	} 
	
	BIGNUM* r1 = BN_new();
	BN_zero(r1);
	BN_mod_add(r1, r1, s[2], param->p, ctx);
	BN_mod_add(r1, r1, sp[1], param->p, ctx);
	BN_mod_add(r1, r1, w, param->p, ctx);
	
	BIGNUM* r2 = BN_new();
	BN_zero(r2);
	BN_mod_add(r2, r2, s[0], param->p, ctx);
	BN_mod_add(r2, r2, wtil, param->p, ctx);
  
	if (BN_cmp(l1, r1) != 0){
		printf(">>>>>>>>>>>>>>> l1 != l2 :(\n");
		printf("%s != %s\n", BN_bn2dec(l1), BN_bn2dec(l2));
		return 0;
	}
  
	if (BN_cmp(l2, r2) != 0){
		printf(">>>>>>>>>>>>>>> r1 != r2 :(\n");
		printf("%s != %s\n", BN_bn2dec(r1), BN_bn2dec(r2));
		return 0;
	}
  
	return 1;
}

int PoC(pHashParam* param, hashVal* H, EC_POINT* com, BIGNUM* sumPi, BIGNUM* sumR, BIGNUM* sp, BIGNUM* sh){
/*    printf("PoE\n");*/
    
    BIGNUM* kpi = PSalt(param);
    BIGNUM* ksp = PSalt(param);
    BIGNUM* kr = PSalt(param);
    BN_CTX* ctx = BN_CTX_new();
    
    EC_POINT* temp=EC_POINT_new(param->curve);
    
    EC_POINT* t1 = EC_POINT_new(param->curve);
    EC_POINT_mul(param->curve, t1, NULL, param->g, ksp, ctx);
    
    EC_POINT* t2 = EC_POINT_new(param->curve);
    EC_POINT_mul(param->curve, t2, NULL, H->H1, kpi, ctx);
    
    EC_POINT* t3 = commit(param,kpi,kr);
    
    BIGNUM* challenge= PSalt(param);
    
    BIGNUM* a1 = BN_new();
    BN_mod_mul(a1, challenge, sp, param->p, ctx);
    BN_mod_add(a1, ksp, a1, param->p, ctx);
    
    BIGNUM* a2 = BN_new();
    BN_mod_mul(a2, challenge, sumPi, param->p, ctx);
    BN_mod_sub(a2, kpi, a2, param->p, ctx);
    
    BIGNUM* a4 = BN_new();
    BN_mod_mul(a4, challenge, sumR, param->p, ctx);
    BN_mod_sub(a4, kr, a4, param->p, ctx);
    
    EC_POINT* left=EC_POINT_new(param->curve);
    EC_POINT* right=EC_POINT_new(param->curve);
    
    EC_POINT_mul(param->curve, left, NULL, param->g, a1, ctx);
    EC_POINT_mul(param->curve, right, NULL, H->H1, challenge, ctx);
    EC_POINT_add(param->curve, right, right,t1, ctx);
    
    if(EC_POINT_cmp(param->curve, left, right, ctx)!=0){
        printf("g^a1 !=t1H1^c\n");
        return 0;
    }
    
    EC_POINT_mul(param->curve, right, NULL, param->h, sh, ctx);
    EC_POINT_invert(param->curve, right, ctx);
    EC_POINT_add(param->curve, right, H->H2, right, ctx);
    EC_POINT_mul(param->curve, right, NULL, right, challenge, ctx);
    EC_POINT_mul(param->curve, temp, NULL, H->H1, a2, ctx);
    EC_POINT_add(param->curve, right, right, temp, ctx);
    
    if(EC_POINT_cmp(param->curve, t2, right, ctx)!=0){
        printf("H1^a2 * (H2/h^s_H)^c != t2\n");
        return 0;
    }
    
    EC_POINT_mul(param->curve, temp, NULL, param->h, a4, ctx);
    EC_POINT_mul(param->curve, right, NULL, param->g, a2, ctx);
    EC_POINT_add(param->curve, temp, right, temp, ctx);
    EC_POINT_mul(param->curve, right, NULL, com, challenge, ctx);
    EC_POINT_add(param->curve, right, right, temp, ctx);
    
    if(EC_POINT_cmp(param->curve, t3, right, ctx)!=0){
        printf("g^a2 * h^a4 * C^c != t3\n");
        return 0;
    }
    
    return 1;
}



