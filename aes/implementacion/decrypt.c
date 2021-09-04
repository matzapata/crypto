/*
FUNCIONAL.
Falta agregar padding, o bien podes coordinar cantidad de 
bytes entre encript y decrypt e ignorar el resto en el ultimo bloque
*/

#include <stdlib.h>
#include <stdio.h>
#include "aes256.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    aes256_context ctx;
    uint8_t key[32] = "key";
    uint8_t buf[16];

    aes256_init(&ctx, key);

    FILE *src_file = fopen("./tests/dest.txt", "r");
    FILE *dest_file = fopen("./tests/dest_dec.txt", "w");

    if (src_file == NULL || dest_file == NULL)
    {
        printf("Error. No se pudieron abrir los archivos\n");
        exit(1);
    }
    else
    {
        uint8_t r = 0;
        uint8_t w = 0;
        do
        {
            memset(buf, 0, 16);
            r = fread(buf, sizeof(uint8_t), 16, src_file);
            if (r != 0)
            {
                aes256_decrypt_ecb(&ctx, buf);
                w = fwrite(buf, sizeof(uint8_t), 16, dest_file);
            }
        } while (r != 0 && r==w);
    }
    fclose(dest_file);
    fclose(src_file);

    aes256_done(&ctx);

    return 0;
}
