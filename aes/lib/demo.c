
#include <stdlib.h>
#include <stdio.h>
#include "aes256.h"
#include <string.h>

#define DUMP(s, i, buf, sz)          \
    {                                \
        printf(s);                   \
        for (i = 0; i < (sz); i++)   \
            printf("%02x ", buf[i]); \
        printf("\n");                \
    }


int main(int argc, char *argv[])
{
    aes256_context ctx;
    uint8_t key[32] = "key";
    uint8_t src[] = "hola";
    uint8_t buf[16];
    uint8_t i;

    // NOTA: Solucion padding. No es la opcion mas segura pero funciona
    strncpy(buf, src, 16);

    /* put a test vector */
    // for (i = 0; i < sizeof(buf);i++) buf[i] = i * 16 + i;
    // for (i = 0; i < sizeof(key);i++) key[i] = i;

    // DUMP("txt: ", i, buf, sizeof(buf));
    printf("txt: %s\n", buf);
    DUMP("key: ", i, key, sizeof(key));
    printf("---\n");

    aes256_init(&ctx, key);
    aes256_encrypt_ecb(&ctx, buf);

    DUMP("enc: ", i, buf, sizeof(buf));
    printf("tst: 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89\n");

    aes256_init(&ctx, key);
    aes256_decrypt_ecb(&ctx, buf);
    // DUMP("dec: ", i, buf, sizeof(buf));
    printf("dec: %s\n", buf);

    aes256_done(&ctx);

    return 0;
} /* main */