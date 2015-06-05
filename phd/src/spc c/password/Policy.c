//
//  Policy.c
//  PSI
//
//  Created by Changyu Dong on 10/03/2015.
//  Copyright (c) 2015 Changyu Dong. All rights reserved.
//


#include "Policy.h"

int parsePolicy(char* policyStr, int size,Policy** P){
    //get rid of leading space if any
    while(isspace(*policyStr)&&size>0){
        policyStr++;
        size--;
    }
    if(size==0){
        printf("policy string is empty\n");
        return -1;
    }

    
    Policy* pol= calloc(1, sizeof(Policy));
    
    //first letter to decide 
    if(*policyStr=='A'){
        pol->topIsThresh=0;

    }else{
        pol->topIsThresh=digitToInt(*policyStr);

    }
    assert(pol->topIsThresh!=-1);
    policyStr+=2;
    size-=2;
    
    //second level
    //each level2 policy should be 5 characters
    while(size>0){
        policyStr+=1;
        if(*policyStr=='D'){
            policyStr+=2;
            pol->digitThresh=digitToInt(*policyStr);
            assert(pol->digitThresh>=0);
            
        }else if(*policyStr=='L'){
            policyStr+=2;
            pol->lowerCaseThresh=digitToInt(*policyStr);
            assert(pol->lowerCaseThresh>=0);
            
        }else if(*policyStr=='S'){
            policyStr+=2;
            pol->symbolThresh=digitToInt(*policyStr);
            assert(pol->symbolThresh>=0);
            
        }else if(*policyStr=='U'){
            policyStr+=2;
            pol->upperCaseThresh=digitToInt(*policyStr);
            assert(pol->upperCaseThresh>=0);
        }else{
            printf("Wrong policy format\n");
            return -1;
        }
        policyStr+=2;
        size-=5;
    }
    
    *P=pol;
    return 0;
}

void parsePassword(Password** pass, char* passStr,int len){
    assert(passStr!=NULL);
    Password* result= calloc(1, sizeof(Password));
    
    result->passStr=passStr;
    result->len=len;
    
    for(int i=0;i<len;i++){
        char ch= passStr[i];
        if(isDigit(ch)){
            addCharToCharset(ch, &(result->digitSet));
            result->digitSet.last->order=i;
        }else if(isLowerCase(ch)){
            addCharToCharset(ch, &(result->lowerCaseSet));
            result->lowerCaseSet.last->order=i;
        }else if(isUpperCase(ch)){
            addCharToCharset(ch, &(result->upperCaseSet));
            result->upperCaseSet.last->order=i;
        }else if(isSymbol(ch)){
            addCharToCharset(ch, &(result->symbolSet));
            result->symbolSet.last->order=i;
        }else{
            printf("invalid character: %c\n",ch);
            exit(-1);
        }
    }
    
    *pass= result;
}


void printCharset(charSet* set){
    assert(set!=NULL);
    if(set->size==0){
        printf("Empty set.\n");
    }else{
        printf("Set size = %d\n",set->size);
        indexedChar* current=set->first;
        do {
            printf("%c",current->ch[0]);
            printf("%u(%u)",current->ch[1],current->order);
            
            if(current->ctxts!=NULL){
                printf("[");
                if(current->ctxts->share!=NULL){
                    printf("%s",BN_bn2hex(current->ctxts->share));
                }
                
            }
            printf("] ");
            
            
            current=current->next;
        } while (current!=NULL);
        printf("\n");
    }
}

void printPassword(Password* pass){
    printf("%s\n",pass->passStr);
    printf("password length: %u\n",pass->len);
    printf("Digit characters: \n");
    printCharset(&(pass->digitSet));
    printf("Lowercase characters: \n");
    printCharset(&(pass->lowerCaseSet));
    printf("Symbol characters: \n");
    printCharset(&(pass->symbolSet));
    printf("Uppercase characters: \n");
    printCharset(&(pass->upperCaseSet));
    
}

int satisfies(Password* pass, Policy* P){
    int result=1;
    
    if(P->topIsThresh){
        int thresh=P->topIsThresh;
        
        if(P->digitThresh!=0){
            if(pass->digitSet.size>=P->digitThresh){
                thresh--;
            }
        }
        
        if(P->lowerCaseThresh!=0){
            if(pass->lowerCaseSet.size>=P->lowerCaseThresh){
                thresh--;
            }
        }
        
        if(P->symbolThresh!=0){
            if(pass->symbolSet.size>=P->symbolThresh){
                thresh--;
            }
        }
        
        if(P->upperCaseThresh!=0){
            if(pass->upperCaseSet.size>=P->upperCaseThresh){
                thresh--;
            }
        }
        
        if (thresh>0) {
            result=0;
        }

    }else{
        if(P->digitThresh!=0){
            if(pass->digitSet.size<P->digitThresh){
                result=0;
            }
        }
        
        if(P->lowerCaseThresh!=0){
            if(pass->lowerCaseSet.size<P->lowerCaseThresh){
                result=0;
            }
        }
        
        if(P->symbolThresh!=0){
            if(pass->symbolSet.size<P->symbolThresh){
                result=0;
            }
        }
        
        if(P->upperCaseThresh!=0){
            if(pass->upperCaseSet.size<P->upperCaseThresh){
                result=0;
            }
        }
        
    }
    return result;
}

void minimalSatisfiableSet(Password* pass, Policy* P,minimalSet** result){
    //an empty set
    
    minimalSet* set=calloc(1, sizeof(minimalSet));
    
  
    if(P->topIsThresh){
        int thresh=P->topIsThresh;
        
        if(P->digitThresh!=0){
            if(pass->digitSet.size>=P->digitThresh){
                thresh--;
            }
            int counter= P->digitThresh;
            indexedChar* current= pass->digitSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->digitSet));
                current=current->next;
                counter--;

            }
        }
        
        
        if(thresh!=0&&P->lowerCaseThresh!=0){
            if(pass->lowerCaseSet.size>=P->lowerCaseThresh){
                thresh--;
            }
            
            int counter= P->lowerCaseThresh;
            indexedChar* current= pass->lowerCaseSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->lowerCaseSet));
                current=current->next;
                counter--;
                
            }
        }
    
        if(thresh!=0&&P->symbolThresh!=0){
            if(pass->symbolSet.size>=P->symbolThresh){
                thresh--;
            }
            int counter= P->symbolThresh;
            indexedChar* current= pass->symbolSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->symbolSet));
                current=current->next;
                counter--;
                
            }
        }
        
        
        if(thresh!=0&&P->upperCaseThresh!=0){
            if(pass->upperCaseSet.size>=P->upperCaseThresh){
                thresh--;
            }
            int counter= P->upperCaseThresh;
            indexedChar* current= pass->upperCaseSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->upperCaseSet));
                current=current->next;
                counter--;
                
            }
        }
        
    }else{
        if(P->digitThresh!=0){
            int counter= P->digitThresh;
            indexedChar* current= pass->digitSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->digitSet));
                current=current->next;
                counter--;
                
            }
        }
        
        
        if(P->lowerCaseThresh!=0){
            int counter= P->lowerCaseThresh;
            indexedChar* current= pass->lowerCaseSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->lowerCaseSet));
                current=current->next;
                counter--;
                
            }
        }
        
        if(P->symbolThresh!=0){
            int counter= P->symbolThresh;
            indexedChar* current= pass->symbolSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->symbolSet));
                current=current->next;
                counter--;
                
            }
        }
        
        
        if(P->upperCaseThresh!=0){
            int counter= P->upperCaseThresh;
            indexedChar* current= pass->upperCaseSet.first;
            while(counter>0){
                copyIndexedCharToCharset(current, &(set->upperCaseSet));
                current=current->next;
                counter--;
                
            }
        }
  
        
    }
    
    *result=set;
}

int charToIntX(indexedChar* ch){
    //char
    int i= ch->ch[0];
    i+=(128*(ch->ch[1]-1));
    return i;
}
