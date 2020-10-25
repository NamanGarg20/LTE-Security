//
//  eea2.c
//  
//
//  Created by NAMAN GARG on 10/20/20.
//

#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <assert.h>

#define MAX_LEN 2048

extern int OPENSSL_cleanse(void *ptr, size_t len);
u_int32_t OPENSSL_ia32cap_P[4] = { 0 };

struct ctr_state {
    unsigned char ivec[16];
    unsigned int num;
    unsigned char ecount[16];
};

void remove_spaces (unsigned char*  str_t, const unsigned char*  str_u)
{
  while (*str_u != '\0')
  {
    if(!isspace(*str_u))
    {
      *str_t = *str_u;
      str_t++;
    }
    str_u++;
  }
  *str_t = '\0';
}
char *substring(char *string, int position, int length)
{
   char *p;
   int c;
 
   p = malloc(length+1);
   
   if (p == NULL)
   {
      printf("Unable to allocate memory.\n");
      exit(1);
   }
 
   for (c = 0; c < length; c++)
   {
      *(p+c) = *(string+position-1);
      string++;
   }
 
   *(p+c) = '\0';
 
   return p;
}

int hex2data(unsigned char *bytearray,  unsigned char *hexstring, int length)
{
    for (int i = 0; i < (length/2); i++) {
        sscanf((char *)hexstring + 2*i, "%02x",(unsigned int*) &bytearray[i]);
        //printf("%02x", bytearray[i]);
    }

    return 0;
}

void padding ( unsigned char *lastb, unsigned char *pad, int length, int n )
{
    int j;
    int m;
    /* original last block */
    for ( j=0, m=n; j<16; j++, m++ ) {
        if ( j < length ) {
            pad[j] = lastb[m];
        } else if ( j == length ) {
            pad[j] = 0x80;
        } else {
            pad[j] = 0x00;
        }
    }
    
}


void ctr_init(const unsigned char *key,unsigned int count,unsigned int bearer,unsigned int dir, unsigned char * data, int length, int blockNum,  unsigned char *dataOut)
{
    int j, m = 0, n = 0;
    unsigned char counterBlock[16];
    unsigned char keyStreamBlock[16];
    
    unsigned int total_len = length ;
   unsigned int endPos = (total_len + 127) / 128, endRes = (total_len % 128) / 8 ;  //assume that the data is byte-aligned.
    unsigned int startPos = 0 , startRes = 0;
    unsigned int h = 0, k = 0;
    for(j=0;j<16;j++)
    {
    if (j<4)//count
    {
        counterBlock[j] =(unsigned char) (count>>(8*(3-j)));
    }
    else if (j == 4)//bearer+dir
    {
        counterBlock[j] = (unsigned char)(bearer<<3) | (dir<<2);
    }
    else if(j < 14)//0x00
    {
        counterBlock[j] = 0;
    }
    else
    {
        counterBlock[14] = 0;
        counterBlock[15] =blockNum;
    }
    }

    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    unsigned long newLength = (length +3 )/4 -1;
    
    AES_encrypt(counterBlock, keyStreamBlock, &aes_key); // generate keystream


    h =(blockNum == startPos) ? startRes : 0;
    k =(blockNum == endPos) ? ((endRes == 0) ? 16 : endRes) : 16;
      n =(blockNum == 0) ? 0:(16 +(blockNum -1)*16);
    
    for (j = h, m = n; j < k ; j++, m++)
    {
        dataOut[m] = data[m] ^ keyStreamBlock[j]; // plaintext xor keystream

    }
    

}



// function only processes one block data, so we need loop call it
void cipher_eea2(const unsigned char *key,unsigned int count,unsigned int bearer,unsigned int dir, unsigned char *data, int length, unsigned char *dataOut)
{
    unsigned int    i = 0;
    unsigned int    start_block = 0;
    unsigned int     end_block = (length + 127 ) / 128 - 1;

    for (i= start_block; i <= end_block; i++)
    {
        ctr_init(key, count, bearer, dir, data, length, i, dataOut);
    }
   
    int end = ((length +length%8 ) /8) -1;
    
        for (i = 0; i<=  end ; i++){
              printf("%02x", dataOut[i]);
                if ( (i%4) == 3 ) printf(" ");
    }
    
    
}

int main(int argc, char* argv[]){
      if (argc != 2)
      {
          printf( "Usage: ./Ciphering input_file.txt \n" );
          return 0;
      }
       FILE* fp;
        fp = fopen(argv[1], "r");
        if (fp == NULL) {
          perror("Failed: ");
          return 1;
        }
    
        int i =0;
        char ln[10][MAX_LEN];
        // -1 to allow room for NULL terminator for really long string
        while (fgets(ln[i], sizeof(ln[i]), fp)) i++;
        
        // inputs from file
        unsigned char * key = (unsigned char *)substring(ln[0], 7, strlen(ln[0]));
            
        char* count = substring(ln[1], 9, strlen(ln[1]));
        unsigned int COUNT;
        int x =(unsigned int) sscanf(count, "%x", &COUNT);
        
        char * Bearer = (char *)substring(ln[2], 10, strlen(ln[2]));
        unsigned int BEARER;
  
        int y =(unsigned int) sscanf(Bearer, "%x", &BEARER);
    
       unsigned int Direction = atoi(substring(ln[3], 13, strlen(ln[3])));
        
        int length = (int)atoi(substring(ln[4], 10, strlen(ln[4])));
       
        unsigned char * plain = (unsigned char *)substring(ln[5], 13, strlen(ln[5]));
       // printf("String Plaintext %s  ", plain);
        
    fclose(fp);
    int end = ((length +length%8 ) /8);
            int newlength = (length+1)/2;
            unsigned char newData[newlength];
            remove_spaces(newData, plain); // removes spaces
           
            unsigned char dataIn[end];
            hex2data(dataIn, newData, (length+3)/4);// converts into array of hex bytes
    
            unsigned char dataOut[end];
            //unsigned char recovered[end];
            
    unsigned char newKey[16];
     remove_spaces(newKey, key);// removes spaces
     unsigned char enc_key[16];
    hex2data(enc_key, newKey, strlen((char*)newKey));// converts into array of hex bytes
    
         printf("Ciphertext: \n");
       cipher_eea2(enc_key,COUNT, BEARER, Direction, dataIn, length, dataOut);
        
       // printf("\n");
               
       // cipher_eea2(enc_key,COUNT, BEARER, Direction, dataOut, length, recovered);

        return 0;
    }
