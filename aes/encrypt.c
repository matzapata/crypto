
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

#include <stdlib.h>

FILE *src_file;
FILE *dest_file;
aes256_context ctx;
uint8_t key[32] = "key";
uint8_t buf[16];
uint8_t i;

int main(int argc, char *argv[])
{
    printf("Encriptando...\n");

    aes256_init(&ctx, key);

    src_file = fopen("./tests/src.txt", "r");
    dest_file = fopen("./tests/dest.txt", "w");

    if (src_file == NULL || dest_file == NULL)
        exit(1);
    else
    {
        printf("\nEl contenido del archivo de prueba es \n\n");

        uint8_t r = 0;
        uint8_t w = 0;
        do
        {
            memset(buf, 0, 16);
            r = fread(buf, sizeof(uint8_t), 16, src_file);
            if (r != 0)
            {
                aes256_encrypt_ecb(&ctx, buf);
                w = fwrite(buf, sizeof(uint8_t), 16, dest_file);
                printf("r=%d : w=%d\n", r, w);
            }
        } while (r != 0);
    }
    fclose(dest_file);
    fclose(src_file);

    aes256_done(&ctx);
    printf("Hecho...\n");

    return 0;
} /* main */

// aes256_context ctx;
// uint8_t key[32] = "key";
// uint8_t buf[16] = "hola";
// uint8_t i;

// /* put a test vector */
// // for (i = 0; i < sizeof(buf);i++) buf[i] = i * 16 + i;
// // for (i = 0; i < sizeof(key);i++) key[i] = i;

// // DUMP("txt: ", i, buf, sizeof(buf));
// printf("txt: %s\n", buf);
// DUMP("key: ", i, key, sizeof(key));
// printf("---\n");

// aes256_init(&ctx, key);
