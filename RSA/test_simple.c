#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, int8_t **argv)
{
  struct public_key_class pub[1];
  struct private_key_class priv[1];
  rsa_gen_keys(pub, priv, "./implementacion/primes.txt");

  printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (int64_t )priv->modulus, (int64_t ) priv->exponent);
  printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (int64_t )pub->modulus, (int64_t ) pub->exponent);
  
  // int8_t message[] = "123abc";
  // Prueba con output de sha
  int8_t message[] = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";
  int i;

  printf("Original:\n");
  printf("%s\n", message);

  int64_t  *encrypted = rsa_encrypt(message, sizeof(message), pub);
  if (!encrypted){
    fprintf(stderr, "Error in encryption!\n");
    return 1;
  }

  printf("\nEncrypted:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld", (int64_t )encrypted[i]);
  }  
  
  int8_t *decrypted = rsa_decrypt(encrypted, 8*sizeof(message), priv);
  if (!decrypted){
    fprintf(stderr, "Error in decryption!\n");
    return 1;
  }
  printf("\nDecrypted:\n");
  printf("%s\n", decrypted);  

  
  printf("\n");
  free(encrypted);
  free(decrypted);
  return 0;
}
