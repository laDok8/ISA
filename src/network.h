#ifndef ISA_NETWORK_H
#define ISA_NETWORK_H
#include <cstdint>
#include <string>

#define MTU 1500
#define PAYLOAD 1460

// checksum function taken from http://www.faqs.org/rfcs/rfc1071.html
uint16_t checksum(unsigned char * addr, unsigned count );

enum packet_type {
        name,
        data,
        end
};

#define PROTOSIZE (sizeof(packet_type)+sizeof(int))
struct packet_body{
    packet_type typ;
    int dropB;
    uint8_t* data;
};

//encrpyt and decrypt fuctions insipred by SSL library wiki:
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);



#endif //ISA_NETWORK_H
