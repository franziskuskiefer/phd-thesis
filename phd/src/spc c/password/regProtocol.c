//
//  regProtocol.c
//  PSI
//
//  Created by Changyu Dong on 16/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//

#include <stdio.h>
#include "regProtocol.h"
#include <string.h>
#include "GarbledBF.h"
#include <math.h>


void generatePoly(server* s){
    Policy* pol=s->pol;
    int lv1t=pol->topIsThresh;
    //int lv1n=0;
    
    BIGNUM* secrets[5];
    
    secrets[0]=BN_new();
    BN_CTX* ctx=BN_CTX_new();
    
    s->polySet=calloc(1, sizeof(polynomialSet));
    
    if(lv1t ==0){
        BN_zero(secrets[0]);
        if(pol->digitThresh!=0){
            secrets[1]=BN_new();
            BN_rand_range(secrets[1], s->p);
            BN_mod_add(secrets[0], secrets[0], secrets[1], s->p, ctx);
            createRandomPoly(pol->digitThresh-1, s->p, &(s->polySet->digPoly));
            s->polySet->digPoly->coefficents[0]=secrets[1];
            
        }
        
        if(pol->lowerCaseThresh!=0){
            secrets[2]=BN_new();
            BN_rand_range(secrets[2], s->p);
            BN_mod_add(secrets[0], secrets[0], secrets[2], s->p, ctx);
            createRandomPoly(pol->lowerCaseThresh-1, s->p, &(s->polySet->lowPoly));
            s->polySet->lowPoly->coefficents[0]=secrets[2];
        }
        
        if(pol->symbolThresh!=0){
            secrets[3]=BN_new();
            BN_rand_range(secrets[3], s->p);
            BN_mod_add(secrets[0], secrets[0], secrets[3], s->p, ctx);
            createRandomPoly(pol->symbolThresh-1, s->p, &(s->polySet->symPolyl));
            s->polySet->symPolyl->coefficents[0]=secrets[3];
        }
        
        if(pol->upperCaseThresh!=0){
            secrets[4]=BN_new();
            BN_rand_range(secrets[4], s->p);
            BN_mod_add(secrets[0], secrets[0], secrets[4], s->p, ctx);
            createRandomPoly(pol->upperCaseThresh-1, s->p, &(s->polySet->upPoly));
            s->polySet->upPoly->coefficents[0]=secrets[4];
        }
        
        createRandomPoly(0, s->p, &(s->polySet->lv1Poly));
        s->polySet->lv1Poly->coefficents[0]=secrets[0];
    
    }else{
        //level 1 secret
        BN_rand_range(secrets[0], s->p);
        createRandomPoly(lv1t-1, s->p, &(s->polySet->lv1Poly));
        s->polySet->lv1Poly->coefficents[0]= secrets[0];
        //create shares for the lower level
        
        if(pol->digitThresh!=0){
            secrets[1]=BN_new();
            shareGen(s->polySet->lv1Poly, s->xs[1], s->p, secrets[1]);
            createRandomPoly(pol->digitThresh-1, s->p, &(s->polySet->digPoly));
            s->polySet->digPoly->coefficents[0]=secrets[1];
            
        }
        
        if(pol->lowerCaseThresh!=0){
            secrets[2]=BN_new();
            shareGen(s->polySet->lv1Poly, s->xs[2], s->p, secrets[2]);
            createRandomPoly(pol->lowerCaseThresh-1, s->p, &(s->polySet->lowPoly));
            s->polySet->lowPoly->coefficents[0]=secrets[2];
        }
        
        if(pol->symbolThresh!=0){
            secrets[3]=BN_new();
            shareGen(s->polySet->lv1Poly, s->xs[3], s->p, secrets[3]);
            createRandomPoly(pol->symbolThresh-1, s->p, &(s->polySet->symPolyl));
            s->polySet->symPolyl->coefficents[0]=secrets[3];
        }
        
        if(pol->upperCaseThresh!=0){
            secrets[4]=BN_new();
            shareGen(s->polySet->lv1Poly, s->xs[4], s->p, secrets[4]);
            createRandomPoly(pol->upperCaseThresh-1, s->p, &(s->polySet->upPoly));
            s->polySet->upPoly->coefficents[0]=secrets[4];
        }
    }
    
  
    
}


void prepareXs(server* s){
    Policy* pol=s->pol;
    int maxT=0;
    
    if(pol->topIsThresh>maxT){
        maxT=pol->topIsThresh;
    }
    if(pol->digitThresh>maxT){
        maxT=pol->digitThresh;
    }
    if(pol->lowerCaseThresh>maxT){
        maxT=pol->lowerCaseThresh;
    }
    if(pol->symbolThresh>maxT){
        maxT=pol->symbolThresh;
    }
    if(pol->upperCaseThresh>maxT){
        maxT=pol->upperCaseThresh;
    }
    
    int size= 128*maxT;
    
    s->xs=calloc(size, sizeof(BIGNUM**));
    
    for(int i=0;i<size;i++){
        s->xs[i]=calloc(maxT, sizeof(BIGNUM*));
        for(int j=0;j<maxT;j++){
            s->xs[i][j]=BN_new();
            unsigned long val= (unsigned long)pow(i,j);
            BN_set_word(s->xs[i][j], val);
            //printf("%s ",BN_bn2dec(s->xs[i][j]));
        }
        //printf("\n");
    }
    
}

void addData(server* s){
    Policy* pol= s->pol;
    minimalSet* sets = s->setS;
    
    if(pol->digitThresh>=0){
        for(int i=0;i<pol->digitThresh;i++){
            for(char ch =48;ch<=57;ch++){
                addCharToCharset(ch, &(sets->digitSet));
            }
        }
    }
    
    if(pol->lowerCaseThresh>=0){
        for(int i=0;i<pol->lowerCaseThresh;i++){
            for(char ch =97;ch<=122;ch++){
                addCharToCharset(ch, &(sets->lowerCaseSet));
            }
        }
    }
    
    if(pol->symbolThresh>=0){
        for(int i=0;i<pol->symbolThresh;i++){
            for(char ch =33;ch<=126;ch++){
                if(isSymbol(ch)){
                    addCharToCharset(ch, &(sets->symbolSet));
                }
            }
        }
    }
    
    if(pol->upperCaseThresh>=0){
        for(int i=0;i<pol->upperCaseThresh;i++){
            for(char ch =65;ch<=90;ch++){
                addCharToCharset(ch, &(sets->upperCaseSet));
            }
        }
    }
    
    
    
}


void printPolynomialSet(polynomialSet* pset){
    printf("top level polynomial: ");
    printPolynomial(pset->lv1Poly);
    printf("digit polynomial: ");
    printPolynomial(pset->digPoly);
    printf("lower case polynomial: ");
    printPolynomial(pset->lowPoly);
    printf("symbol polynomial: ");
    printPolynomial(pset->symPolyl);
    printf("uppercase polynomial: ");
    printPolynomial(pset->upPoly);

}

void sharesForChars(charSet* set, BIGNUM*** xs,BIGNUM* p, Polynomial* pol){
    indexedChar* ch=set->first;
    
    do {
        int x= charToIntX(ch);
        
        if(ch->ctxts==NULL){
            ch->ctxts=calloc(1, sizeof(cryptoChar));
        }
        
        ch->ctxts->xs=xs[x];
        ch->ctxts->share=BN_new();
        
        shareGen(pol, ch->ctxts->xs, p, ch->ctxts->share);
        
        ch=ch->next;
    } while (ch!=NULL);
    
}

void serverShares(server* s){
    if(s->polySet->digPoly!=NULL){
        sharesForChars(&(s->setS->digitSet), s->xs, s->p, s->polySet->digPoly);
    }
    
    if(s->polySet->lowPoly!=NULL){
        sharesForChars(&(s->setS->lowerCaseSet), s->xs, s->p, s->polySet->lowPoly);
    }
    
    if(s->polySet->symPolyl!=NULL){
        sharesForChars(&(s->setS->symbolSet), s->xs, s->p, s->polySet->symPolyl);
    }
    if(s->polySet->upPoly!=NULL){
        sharesForChars(&(s->setS->upperCaseSet), s->xs, s->p, s->polySet->upPoly);
    }
}


void createServer(int pSize, char* policy,int polLength,server** s){
    server* result= calloc(1, sizeof(server));
    
    //generates prime p
    result->p=BN_new();
    BN_generate_prime(result->p, pSize, 0, NULL, NULL, NULL, NULL);
    
    //parse policy
    parsePolicy(policy, polLength, &(result->pol));
    
    //prepare xs
    //generate x values for secret sharing
    prepareXs(result);
    
    //polynomials
    generatePoly(result);
    
    //prepare data
    result->setS=calloc(1, sizeof(minimalSet));
    addData(result);
    
    //generate shares
    serverShares(result);
    
    MD_Create(&(result->MD), 80);
    
    *s=result;
}


void xForChars(charSet* set, BIGNUM*** xs){
    indexedChar* ch=set->first;
    
    do {
        int x= charToIntX(ch);
        
        if(ch->ctxts==NULL){
            ch->ctxts=calloc(1, sizeof(cryptoChar));
        }
        
        ch->ctxts->xs=xs[x];
         
        ch=ch->next;
    } while (ch!=NULL);
    
}

void linkCharToXClient(client*c, BIGNUM*** xs){
    //minimalSet* sets=c->setC;
    
    if(c->pas->digitSet.size!=0){
        xForChars(&(c->pas->digitSet), xs);
    }
    
    if(c->pas->lowerCaseSet.size!=0){
        xForChars(&(c->pas->lowerCaseSet), xs);
    }
    
    if(c->pas->symbolSet.size!=0){
        xForChars(&(c->pas->symbolSet), xs);
    }
    
    if(c->pas->upperCaseSet.size!=0){
        xForChars(&(c->pas->upperCaseSet), xs);
    }
    
    
}

void createClient(BIGNUM* p, BIGNUM*** xs,Policy* policy,char* password, int passLen,client** c){
    client* result=calloc(1, sizeof(client));
    
    result->p=p;
    result->pol=policy;
    
    parsePassword(&(result->pas), password, passLen);
    
    linkCharToXClient(result, xs);
    
    MD_Create(&(result->MD), 80);
    
    result->passhash=calloc(result->MD->digestLen, sizeof(char));
    
    MD_Digest(result->MD, password, passLen, result->passhash);

    *c=result;
}

void computeuis(charSet* set, RSAPK* pk,char* k, MessageDigest* md,BIGNUM** result){
    indexedChar* ch=set->first;
    
    char* ba = calloc(md->digestLen, sizeof(char));
    char* keyedi= calloc(md->digestLen+4, sizeof(char));
    BIGNUM* temp=BN_new();
    BN_CTX* ctx= BN_CTX_new();
    do {        
        //ri
        //k||i

        memcpy(keyedi, k, md->digestLen);
        memcpy(keyedi+md->digestLen,&(ch->order),4);
        //f(k||i)
        MD_Digest(md, keyedi, md->digestLen+4, ba);
        
        ch->ctxts->ri=BN_new();
        
        BN_bin2bn(ba, md->digestLen, ch->ctxts->ri);
        
        //H(c_i)
        
        MD_Digest(md, ch->ch, 2, ba);
        
        ch->ctxts->u_i=BN_new();
        
        BN_bin2bn(ba, md->digestLen, ch->ctxts->u_i);
        
        //ri^e
        BN_mod_exp(temp, ch->ctxts->ri, pk->e, pk->N, ctx);
        
        //H(c_i)r_i^e
        BN_mod_mul(ch->ctxts->u_i, ch->ctxts->u_i, temp, pk->N, ctx);
        
        
        *result=ch->ctxts->u_i;
        result++;
        ch=ch->next;
    } while (ch!=NULL);
    
}

int prepareuis(client* c, RSAPK* pk, BIGNUM*** result){
    int len= 0;
    
    if(c->pas->digitSet.size!=0){
        len+=c->pas->digitSet.size;
    }
    if(c->pas->lowerCaseSet.size!=0){
        len+=c->pas->lowerCaseSet.size;
    }
    if(c->pas->symbolSet.size!=0){
        len+=c->pas->symbolSet.size;
    }
    if(c->pas->upperCaseSet.size!=0){
        len+=c->pas->upperCaseSet.size;
    }
    
    BIGNUM** uis= calloc(len, sizeof(BIGNUM*));
    
    *result=uis;
    
    if(c->pas->digitSet.size!=0){
        computeuis(&(c->pas->digitSet), pk,c->passhash, c->MD,uis);
        uis+=c->pas->digitSet.size;
    }
    if(c->pas->lowerCaseSet.size!=0){
        computeuis(&(c->pas->lowerCaseSet), pk,c->passhash, c->MD,uis);
        uis+=c->pas->lowerCaseSet.size;
    }
    if(c->pas->symbolSet.size!=0){
        computeuis(&(c->pas->symbolSet), pk,c->passhash, c->MD,uis);
        uis+=c->pas->symbolSet.size;
    }
    if(c->pas->upperCaseSet.size!=0){
        computeuis(&(c->pas->upperCaseSet), pk,c->passhash, c->MD,uis);
    }
    
    
    return len;
}

void hatc(charSet* set,RSAPK* pk, MessageDigest* md, char** result){
    indexedChar* ch=set->first;
    BIGNUM* temp=BN_new();
    BN_CTX* ctx=BN_CTX_new();
    int byteN;
    
    do {
        //r_i^-1
        BN_mod_inverse(temp, ch->ctxts->ri, pk->N, ctx);
        
        //u_i' * r_i^-1
        BN_mod_mul(ch->ctxts->u_i, ch->ctxts->u_i, temp, pk->N, ctx);
        
        
        //hash it
        *result=calloc(md->digestLen, sizeof(char));
        
        byteN=BN_num_bytes(ch->ctxts->u_i);
        
        char* ba= calloc(byteN,sizeof(char));
        BN_bn2bin(ch->ctxts->u_i, ba);
        
        MD_Digest(md, ba, byteN, *result);
        
        result++;
        ch=ch->next;
    } while (ch!=NULL);
    
    
}

void prepareHatC(client*c,RSAPK*pk ){
    minimalSet* set=c->setC;
    
    c->hatCsize=set->digitSet.size+set->lowerCaseSet.size+set->symbolSet.size+set->upperCaseSet.size;
    
    c->hatC=calloc(c->hatCsize,sizeof(char*));
    
    char** temp= c->hatC;
    
    if(set->digitSet.size!=0){
        hatc(&(set->digitSet),pk,c->MD,temp);
        temp+=set->digitSet.size;
    }
    if(set->lowerCaseSet.size!=0){
        hatc(&(set->lowerCaseSet),pk,c->MD,temp);
        temp+=set->lowerCaseSet.size;
    }
    if(set->symbolSet.size!=0){
        hatc(&(set->symbolSet),pk,c->MD,temp);
        temp+=set->symbolSet.size;
    }
    if(set->upperCaseSet.size!=0){
        hatc(&(set->upperCaseSet),pk,c->MD,temp);
    }
    
}

void hatS(charSet* set,RSASK* sk,MessageDigest* md,char** tempHats, char** tempShare){
    indexedChar* ch=set->first;
    char* ba= calloc(md->digestLen, sizeof(char));
    BIGNUM* bn= BN_new();
    BN_CTX* ctx=BN_CTX_new();
    int bnLen;
    char* start;
    do {
        //h(si)
        MD_Digest(md, ch->ch, 2, ba);
        
        //to big integer
        BN_bin2bn(ba, md->digestLen, bn);
        
        //bn^d
        BN_mod_exp(bn, bn, sk->d, sk->N, ctx);
        
        //hash it
        bnLen=BN_num_bytes(bn);
        
        char* ba= calloc(bnLen, sizeof(char));
        BN_bn2bin(bn, ba);
        
        *tempHats=calloc(md->digestLen, sizeof(char));
        
        MD_Digest(md, ba, bnLen, *tempHats);
        
        *tempShare=calloc(shareByteSize,sizeof(char));
        
        bnLen=BN_num_bytes(ch->ctxts->share);
        start=*tempShare+(shareByteSize-bnLen);
        
        BN_bn2bin(ch->ctxts->share, start);
        
        tempHats++;
        tempShare++;
        ch=ch->next;
    } while (ch!=NULL);
}

void prepareHatS(server* s,RSASK* sk ){
    minimalSet* set = s->setS;
    
    s->hatSsize=set->digitSet.size+set->lowerCaseSet.size+set->symbolSet.size+set->upperCaseSet.size;
    
    s->hatS=calloc(s->hatSsize, sizeof(char*));
    s->share=calloc(s->hatSsize, sizeof(char*));
    
    char** tempHats=s->hatS;
    char** tempShare=s->share;
    
    
    if(set->digitSet.size!=0){
        hatS(&(set->digitSet),sk,s->MD,tempHats,tempShare);
        tempHats+=set->digitSet.size;
        tempShare+=set->digitSet.size;
    }
    if(set->lowerCaseSet.size!=0){
        hatS(&(set->lowerCaseSet),sk,s->MD,tempHats,tempShare);
        tempHats+=set->lowerCaseSet.size;
        tempShare+=set->lowerCaseSet.size;
    }
    if(set->symbolSet.size!=0){
        hatS(&(set->symbolSet),sk,s->MD,tempHats,tempShare);
        tempHats+=set->symbolSet.size;
        tempShare+=set->symbolSet.size;
    }
    if(set->upperCaseSet.size!=0){
        hatS(&(set->upperCaseSet),sk,s->MD,tempHats,tempShare);
    }
    
}

void recoverSecret(BIGNUM* p, charSet* set,char** shares,BIGNUM* secret){
    
    BIGNUM*** points= calloc(set->size, sizeof(BIGNUM**));
    
    indexedChar* ch=set->first;
    
    for(int i=0;i<set->size;i++){
        points[i]=calloc(2, sizeof(BIGNUM*));
        points[i][0]= ch->ctxts->xs[1];
        points[i][1]=BN_new();
        BN_bin2bn(shares[i], GBFSigmaByteLen, points[i][1]);
        ch=ch->next;
    }
    
    reconstruct(points, p, set->size, secret);
    
}

