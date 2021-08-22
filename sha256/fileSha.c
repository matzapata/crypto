/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding SHA1
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include <stdint.h>
#include <stdlib.h>

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_file(const char *filename);
void sha256_file(const char *filename)
{
    BYTE buf[16];
    uint8_t out[SHA256_BLOCK_SIZE];

    SHA256_CTX ctx;

    FILE *file;

    sha256_init(&ctx);

    file = fopen(filename, "r");

    if (file == NULL)
        exit(1);
    else
    {

        uint8_t r = 0;
        do
        {
            memset(buf, 0, 16);
            r = fread(buf, sizeof(uint8_t), 16, file);
            if (r != 0)
            {
                // printf("r=%d | buf=%s\n", r, buf);
                sha256_update(&ctx, buf, strlen((char *)buf));
            }
        } while (r != 0);
    }
    fclose(file);

    sha256_final(&ctx, out);

    // Print it
    int i;
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", out[i]);
    }
    printf("\n");
}

int main()
{
    sha256_file("./test.txt");
    return (0);
}
