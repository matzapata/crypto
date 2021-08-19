/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include "aes.h"

/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(BYTE str[], int len)
{
    int idx;

    for (idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}

int aes_ctr_test()
{
    int pass = 1;

    WORD key_schedule[60];
    BYTE enc_buf[128];
    BYTE plaintext[32] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    BYTE ciphertext[32] = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5};
    BYTE iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    BYTE key[32] =  {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    printf("* CTR mode:\n");
    aes_key_setup(key, key_schedule, 256);

    printf("Key          : ");
    print_hex(key, 32);
    printf("\nIV           : ");
    print_hex(iv, 16);

    aes_encrypt_ctr(plaintext, 32, enc_buf, key_schedule, 256, iv);
    printf("\nPlaintext    : ");
    print_hex(plaintext, 32);
    printf("\n-encrypted to: ");
    print_hex(enc_buf, 32);
    pass = pass && !memcmp(enc_buf, ciphertext, 32);

    aes_decrypt_ctr(ciphertext, 32, enc_buf, key_schedule, 256, iv);
    printf("\nCiphertext   : ");
    print_hex(ciphertext, 32);
    printf("\n-decrypted to: ");
    print_hex(enc_buf, 32);
    pass = pass && !memcmp(enc_buf, plaintext, 32);

    printf("\n\n");
    return (pass);
}

int main(int argc, char *argv[])
{
    printf("AES Tests: %s\n", aes_ctr_test() ? "SUCCEEDED" : "FAILED");

    return (0);
}