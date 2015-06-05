//
//  Policy.h
//  PSI
//
//  Created by Changyu Dong on 10/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//

//password policy
//example A:(D,2);(S,1);(L,1)
//--password policy to be mapped to two-level secret sharing
//Policy::=<Level1>:<Level2>

//--top level secret sharing
//--A means all lower level string to be xored together
//--T is an integer meaning the threshold
//Level1::=A|T

//--second level secret sharing
//--at least Threshold characters in Class
//Level2::=(Class, Threshold)|Level2;(Class,Threshold)

//--4 character classes
//--D: digit; L: lower case; S: symbol; U: upper case
//Class::=D|L|S|U

//--threshold is an integer
//Threshold::=int

#ifndef PSI_Policy_h
#define PSI_Policy_h

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/bn.h>

typedef struct Policy{
    // 0 if top level secret sharing is xor sharing
    // other number means the threshold;
    int topIsThresh;
    //thresholds for the four classes
    int digitThresh;
    int lowerCaseThresh;
    int upperCaseThresh;
    int symbolThresh;
}Policy;

typedef struct cryptoChar{
    //x^0,x^1,...,x^n values linked to the character
    BIGNUM** xs;
    
    //ri value used by the client when blinding the character
    BIGNUM* ri;
    
    //u_i value created by the client
    //will be replaced by u_i'*r_i^-1 in the protocol
    BIGNUM* u_i;
    
    //the secret share linked to the character.
    BIGNUM* share;
    
}cryptoChar;

typedef struct indexedChar{
    //ch[0] is the character, ch[1] is the index
    char ch[2];
    
    //pointer for list
    struct indexedChar* next;
    
    //order in password;
    int order;
    
    //cryptographic data used in the protocol 
    cryptoChar* ctxts;

}indexedChar;


typedef struct charSet{
    //characters
    indexedChar* first;
    indexedChar* last;
    //size of the set
    int size;
}charSet;

typedef struct Password{
    // the password string
    char* passStr;
    // password length
    int len;
    //thresholds for the four classes
    charSet digitSet;
    charSet lowerCaseSet;
    charSet upperCaseSet;
    charSet symbolSet;
}Password;

typedef struct minimalSet{
    charSet digitSet;
    charSet lowerCaseSet;
    charSet upperCaseSet;
    charSet symbolSet;
}minimalSet;

//how many times ch appears in set
inline int checkOccurrence(char ch,charSet* set){
    if(set->size==0){
        return 0;
    }else{
        indexedChar* current=set->first;
        int counter=0;
        do {
            if(current->ch[0]==ch){
                counter++;
            }
            current=current->next;
        } while (current!=NULL);
        return counter;
    }
}


// add a character to set
inline void addCharToCharset(char ch,charSet* set){
    //first character in the set
    if(set->first==NULL){
        set->first=calloc(1, sizeof(indexedChar));
        set->first->ch[0]=ch;
        set->first->ch[1]=1;
        set->last=set->first;
        set->size=1;
    }else{
        //non-empty set
        //add a node to the end of the list
        indexedChar* temp=calloc(1, sizeof(indexedChar));
        temp->ch[0]=ch;
        temp->ch[1]=checkOccurrence(ch,set)+1;
        set->last->next=temp;
        set->last=temp;
        set->size++;
    }
}

//add an indexed character to set

inline void addIndexedCharToCharset(indexedChar* ch,charSet* set){
    assert(ch!=NULL);
    assert(set!=NULL);
    if(set->first==NULL){
        set->first=ch;
        set->last=ch;
        set->size=1;
    }else{
        set->last->next=ch;
        set->last=ch;
        set->size++;
    }
}

inline void copyIndexedCharToCharset(indexedChar* ch,charSet* set){
    assert(ch!=NULL);
    assert(set!=NULL);
    
    indexedChar* newCH= calloc(1, sizeof(indexedChar));
    
    newCH->ch[0]=ch->ch[0];
    newCH->ch[1]=ch->ch[1];
    newCH->order=ch->order;
    newCH->ctxts=ch->ctxts;
    
    if(set->first==NULL){
        set->first=newCH;
        set->last=newCH;
        set->size=1;
    }else{
        set->last->next=newCH;
        set->last=newCH;
        set->size++;
    }
}

//to a 2d array of chars result[set->size][2];
inline char** charsetToArray(charSet* set){
    if (set->size==0){
        return NULL;
    }
    
    char** result= calloc(set->size, sizeof(char*));
    
    indexedChar* current= set->first;
    int i=0;
    
    do {
        result[i]=current->ch;
        i++;
        current=current->next;
    } while (current!=NULL);
    return result;
}



inline int digitToInt(char d){
    switch (d) {
        case '0':
            return 0;
            break;
        case '1':
            return 1;
            break;
        case '2':
            return 2;
            break;
        case '3':
            return 3;
            break;
        case '4':
            return 4;
            break;
        case '5':
            return 5;
            break;
        case '6':
            return 6;
            break;
        case '7':
            return 7;
            break;
        case '8':
            return 8;
            break;
        case '9':
            return 9;
            break;
        default:
            return -1;
            break;
    }
}
inline int isLowerCase(char ch){
    return ch>=97&&ch<=122;
}

inline int isUpperCase(char ch){
    return ch>=65&&ch<=90;
}

inline int isDigit(char ch){
    return ch>=48&&ch<=57;
}

inline int isSymbol(char ch){
    return (ch>=33&&ch<=47)||(ch>=58&&ch<=64)||(ch>=91&&ch<=96)||(ch>=123&&ch<=126);
}

int charToIntX(indexedChar* ch);

//parse a policy from a string
int parsePolicy(char* policyStr, int size,Policy** P);

void printCharset(charSet* set);

void parsePassword(Password** pass, char* passStr,int len);

void printPassword(Password* pass);

//whether the password satifies the policy
int satisfies(Password* pass, Policy* P);

//return a set of indexed characters, which satisifes P
void minimalSatisfiableSet(Password* pass, Policy* P,minimalSet** result);



#endif
