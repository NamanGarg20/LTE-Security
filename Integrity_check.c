//

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


extern int OPENSSL_cleanse(void *ptr, size_t len);
u_int32_t OPENSSL_ia32cap_P[4] = { 0 };


unsigned char const_Rb[16] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};


static void xor_block(unsigned char *a, unsigned char *b, unsigned char *out)
{
    int i;
    for (i=0;i<16; i++)
    {
        out[i] = a[i] ^ b[i];
    }
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

//prints the ouput in form of 128 bits
static void print128(unsigned char *bytes)
{
    int j;
    for (j=0; j<16;j++) {
        printf("%02x",bytes[j]);
        if ( (j%4) == 3 ) printf(" ");
    }
}

// removes white space between strings
void remove_spaces (unsigned char*  str_trim, const unsigned char*  str_untrim)
{
  while (*str_untrim != '\0')
  {
    if(!isspace(*str_untrim))
    {
      *str_trim = *str_untrim;
      str_trim++;
    }
    str_untrim++;
  }
  *str_trim = '\0';
}

//generate byte array of hex from hex string
int hex2data(unsigned char *bytearray,  unsigned char *hexstring, int length)
{
    for (int i = 0; i < (length/2); i++) {
        sscanf((char *)hexstring + 2*i, "%02x",(unsigned int*) &bytearray[i]);
    }

    return 0;
}

/* AES-CMAC Generation Function */
void shift_left(unsigned char *in ,unsigned char *out)
{
    int i;
    unsigned char overflow = 0;
    for ( i=15; i>=0; i-- ) {
        out[i] = in[i] << 1;
        out[i] |= overflow;
        overflow = (in[i] & 0x80)?1:0;
    }
}

void generateSubkeys(AES_KEY AESkey, unsigned char *K1, unsigned char *K2)
{
    unsigned char keystream_block[16];
    unsigned char Zero_Array[16];
    unsigned char tmp[16];
    int i;
    for ( i=0; i<16; i++ ) Zero_Array[i] = 0;
    
    AES_encrypt(Zero_Array, keystream_block, &AESkey);
    if ( (keystream_block[0] & 0x80) == 0 ) { /* If MostSignificantBit(L) = 0, then K1 = Lkeystream_block << 1 */
        shift_left(keystream_block,K1);
    } else { /* Else K1 = ( Lkeystream_block << 1 ) (+) Rb */
        shift_left(keystream_block,tmp);
        xor_block(tmp,const_Rb,K1);
    }
    if ( (K1[0] & 0x80) == 0 ) {
        shift_left(K1,K2);
    } else {
        shift_left(K1,tmp);
        xor_block(tmp,const_Rb,K2);
    }

}

void padding ( unsigned char *dataBlock, unsigned char *pad, int length )
{
    int j;
    /* original last block */
    for ( j=0; j<16; j++ ) {
        if ( (j+1)*8 < length)
        {
            pad[j] = dataBlock[j];
        }
        else if ((j+1)*8 > length && j*8 < length)
        {
            pad[j] = dataBlock[j];
            pad[j] |= (unsigned char)(1<<((j+1)*8 - length - 1));
        }
        else if ( (j+1)*8 == length )
        {
            pad[j] = dataBlock[j];
            j++;
            pad[j] = 0x80;
        }
        else if( (j+1)*8 > length )
        {
            pad[j] = 0x00;
        }
    }
}

void cmac_generate( unsigned char *key, unsigned char *dataIn, int length, unsigned char *mac, int rem)
{
    unsigned char cipher_block[16],message[16], last_message[16], padded[16];
    unsigned char K1[16], K2[16];
    int n, i, last_block;
    AES_KEY AESkey;
    AES_set_encrypt_key(key, 128, &AESkey);
    generateSubkeys(AESkey,K1,K2);
    n = (length+15) / 16; /* n is number of rounds */
    if ( n == 0 ) {
        n = 1;
        last_block = 0;
    } else {
        if ( (length%16) == 0 && rem == 0) { /* last block is a complete block */
            last_block = 1;
        } else { /* last block is not complete block */
            last_block = 0;
        }
    }
    if ( last_block ) { /* last block is complete block */
        xor_block(&dataIn[16*(n-1)],K1,last_message);
    } else {
        padding(&dataIn[16*(n-1)],padded,rem);
        xor_block(padded,K2,last_message);
    }

    for ( i=0; i<16; i++ ) cipher_block[i] = 0;
    for ( i=0; i<n-1; i++ ) {
        xor_block(cipher_block,&dataIn[16*i],message); /* message := Mi (+) cipher_block */
         /* cipher_block := AES(KEY, message); */
        AES_encrypt(message, cipher_block, &AESkey);

    }
    xor_block(cipher_block,last_message,message);
   
    AES_encrypt(message, cipher_block, &AESkey); // generate keystream for the last block

    for ( i=0; i<4; i++ ) {
        mac[i] = cipher_block[i];
    }
}


void cmac_eia2(unsigned char *key, int count, int bearer, int dir, unsigned char *data, int length, unsigned char *outMac)
{
    int BLENGTH = (length+64+7)/8;
    int rem = (length+64)%128;
    int i = 0, j = 0;

    unsigned char * MessageBlock;
    MessageBlock = (unsigned char*)malloc(BLENGTH);
    /* from count & bearer & dir & data generate M*/
    for(i=0;i<BLENGTH;i++)
    {
        if (i<4)//count
        {
            MessageBlock[i] = (unsigned char)(count>>(8*(3-i)));
        }
        else if (i == 4)//bearer+dir
        {
            MessageBlock[i] = ((unsigned char)bearer<<3) | ((unsigned char)dir<<2);
        }
        else if(i < 8)//0x00
        {
            MessageBlock[i] = 0;
        }
        else
        {
            MessageBlock[i] = data[j];
            j++;
        }
    }

    cmac_generate(key,MessageBlock,BLENGTH,outMac,rem);
    

    printf("LAST CIPHERTEXT BLOCK : ");
    print128(outMac);
    printf("\n");
    
    printf("MAC: ");
    for(int i=0; i<4; i++) printf("%02x",outMac[i]);
    printf("\n");
    


    free(MessageBlock);
}

int main(int argc, char* argv[1]){
    if (argc != 2)
    {
        printf( "Usage: ./Integrity_check input_file.txt \n" );
        return 0;
    }
    FILE* fp;
        fp = fopen(argv[1], "r");
        if (fp == NULL) {
          perror("Failed: ");
          return 1;
        }
    
    
        int i =0;
    int MAX_LEN = 2048;
        char ln[6][MAX_LEN];
        // -1 to allow room for NULL terminator for really long string
        while (fgets(ln[i], sizeof(ln[i]), fp)) i++; // get lines from input file
        
        
        
        char* count = substring(ln[0], 11, strlen(ln[0]));
    unsigned int COUNT;
    if(( unsigned int) sscanf(count, "%x", &COUNT)==0)
         printf("String Count %x  ", COUNT);
        
        char * Bearer = (char *)substring(ln[1], 10, strlen(ln[1]));
       unsigned int BEARER;
       
             int y =(unsigned int) sscanf(Bearer, "%x", &BEARER);
        
       unsigned int DIRECTION = atoi(substring(ln[2], 13, strlen(ln[2])));
        
        const unsigned char* enc_key = (const unsigned char *)substring(ln[3], 6, strlen(ln[3]));
        int length = (int)atoi(substring(ln[4], 10, strlen(ln[4])));
       
        unsigned char * message = (unsigned char *)substring(ln[5], 11, strlen(ln[5]));
       
        
    fclose(fp);
    int newLength = (length+3)/4;
    unsigned char newData[newLength];
    remove_spaces(newData, message);
 
    unsigned char dataIn[newLength];
    hex2data(dataIn, newData, (length+3)/4);
    
    unsigned char dataOut[128];
    
    unsigned char newKey[16];
    remove_spaces(newKey, enc_key);
    unsigned char key[16];
    hex2data(key, newKey,strlen((char*)newKey));

    cmac_eia2(key, COUNT, BEARER, DIRECTION, dataIn, length, dataOut);

     return 0;
 }
