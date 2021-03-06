//
//  GarbledBF.h
//  PSI
//
//  Created by Changyu Dong on 03/03/2013.
//  Copyright (c) 2013 Changyu Dong. All rights reserved.
//

#ifndef PSI_GarbledBF_h
#define PSI_GarbledBF_h
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "RangeHash.h"
#include "AESRandom.h"
#include "Util.h"
#include "RandomSource.h"

//byte length of entry in GBF
#define GBFSigmaByteLen 10


typedef struct GarbledBF{
    uint8_t** data;
    int32_t m;
    int32_t k;
    int32_t* indexes;
    //int32_t MT;
    //uint8_t* bitmap;
    //int32_t bitMapLeadingZeroes;
    //int32_t bitMapByteLen;
}GarbledBF;
//create a garbled bloom filter, m is the size 
int GBF_Create(GarbledBF** filter, int32_t m, int32_t k);


//call this if use the MT functions.
//int GBF_CreateForMT(GarbledBF** filter,int32_t m, int32_t k);

void GBF_Destroy(GarbledBF* filter);


//get the ith entry from the GBF. The entry is a sigma-bytes array.
inline uint8_t* GBF_get(GarbledBF* filter,uint32_t i){
    assert(i<filter->m);
    return filter->data[i];
};


//set the ith entry
inline void GBF_set(GarbledBF* filter,uint32_t i, uint8_t* entry){
    assert(i<filter->m);
    filter->data[i]=entry;
};


/*
 add an element to the GBF
 filter: the GBF
 hashes: k diferent range hashes
 hashNum: k
 element: the element to add.
 eLen:  the size of the element
 ehash: the hash valu of the element it is sigma byte
 rnd: a random generator
 */
void GBF_add(GarbledBF*filter, RangeHash** hashes, int32_t hashNum, uint8_t* element,int32_t eLen, uint8_t* ehash,AESRandom* rnd);



//To be used in multithreading tasks with indexes and random bytes generated by other threads
void GBF_addMT(GarbledBF*filter, int32_t* indexes, int32_t hashNum,uint8_t* ehash,RandomSource* rndSrc);

/*
 * After adding all elements into the garbled bloom filter, insert random
 * strings to all empty slots. After that no modification to the garbled
 * bloom filter should be allowed.
 */
void GBF_doFinal(GarbledBF* filter,AESRandom* rnd);

void GBF_doFinalMT(GarbledBF* filter,RandomSource* rnd);


int GBF_query(GarbledBF* filter, RangeHash** hashes, int32_t hashNum, uint8_t* element,int32_t eLen, uint8_t* ehash);

int GBF_query_With_Indexes(GarbledBF* filter,int32_t* indexes, int32_t hashNum,uint8_t* ehash);

int GBF_query_get_data(GarbledBF* filter, RangeHash** hashes, int32_t hashNum, uint8_t* element,int32_t eLen, uint8_t* ehash);


#endif
