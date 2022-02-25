#include "network.h"
#include <cstdio>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/conf.h>

const unsigned char key[] = "xdokou14\0\0\0\0\0\0\0\0";

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len,ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw "init cypher error";

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        throw "init cypher round error";

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        throw "update cypher round error";
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        throw "final cypher round error";
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len,plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw "init cypher error";

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        throw "init cypher round error";

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        throw "update cypher round error";
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        throw "final cypher round error";
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

uint16_t checksum(unsigned char * addr, unsigned count ){
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     */
    long sum = 0;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += * (unsigned short *)addr;
        addr+=2;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
