#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>


// Definimos fuente de los numeros primos si primes.txt o primes.h
#define TXT 0
#define HEADER 1
#define PRIMES_SRC HEADER


struct public_key_class{
  long long modulus;
  long long exponent;
};

struct private_key_class{
  long long modulus;
  long long exponent;
};

// This function generates public and private keys, then stores them in the structures you
// provide pointers to. The 3rd argument should be the text PRIME_SOURCE_FILE to have it use
// the location specified above in this header.
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, const char *PRIME_SOURCE_FILE);

// This function will encrypt the data pointed to by message. It returns a pointer to a heap
// array containing the encrypted data, or NULL upon failure. This pointer should be freed when 
// you are finished. The encrypted data will be 8 times as large as the original data.
long long *rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key_class *pub);

// This function will decrypt the data pointed to by message. It returns a pointer to a heap
// array containing the decrypted data, or NULL upon failure. This pointer should be freed when 
// you are finished. The variable message_size is the size in bytes of the encrypted message. 
// The decrypted data will be 1/8th the size of the encrypted data.
char *rsa_decrypt(const long long *message, const unsigned long message_size, const struct private_key_class *pub);


long long rsa_modExp(long long b, long long e, long long m);


#endif
