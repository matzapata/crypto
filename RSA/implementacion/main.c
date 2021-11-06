#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>
#include "funciones.h"

void displayHelp();
void WriteKeys();
uint8_t Encrypt();
uint8_t Decrypt();

int8_t main(int32_t argc, int8_t  **argv)
{
    if (argc > 1)
    {
        uint8_t command = atoi(argv[1]);
        if (command == 1)
        {
            printf("WriteKeys\n");
            WriteKeys();
        }
        else if (command == 2)
        {
            printf("Encrypt\n");
            Encrypt();
        }
        else if (command == 3)
        {
            printf("Decrypt\n");
            Decrypt();
        }
        else
        {
            displayHelp();
        }
    }
    else
    {
        displayHelp();
    }

    return 0;
}

void displayHelp()
{
    printf("Faltan argumentos. Ingrese ./main <mode>.\n");
    printf("1 - Genera llaves publica y privada y la almacena en ./keys/priv.key ./keys/pub.key\n");
    printf("2 - Encripta mensaje y lo guarda en ./tests/enc\n");
    printf("3 - Desencripta el mensaje guardado en ./tests/enc\n");
}

void WriteKeys()
{
    generateKeys("./keys/");
}

uint8_t Encrypt()
{
    struct public_key_class *pub = NULL;
    struct private_key_class *priv = NULL;
    loadKeys(&pub, &priv, "./keys/");
    printKeys(pub, priv);

    int8_t  message[16] = "BA:78:16:BF:8F:";
    uint8_t size = 16;

    printf("Original:\n");
    printf("%s\n", message);

    int64_t  *encrypted = rsa_encrypt(message, size, pub);
    if (!encrypted)
    {
        fprintf(stderr, "Error in encryption!\n");
        return 1;
    }

    FILE *enc_file = fopen("./tests/enc", "wb");
    if (fwrite(encrypted, sizeof(int64_t ), size, enc_file) != size)
    {
        printf("File write error.");
    }
    fclose(enc_file);

    free(encrypted);
    return 0;
}

uint8_t Decrypt()
{
    struct public_key_class *pub = NULL;
    struct private_key_class *priv = NULL;
    loadKeys(&pub, &priv, "./keys/");
    printKeys(pub, priv);

    // Prueba con output de sha
    int8_t  message[16] = "BA:78:16:BF:8F:";
    uint8_t size = 16;

    printf("Original:\n");
    printf("%s\n", message);

    // DESENCRIPTAMOS
    int64_t  encrypted_r[16];

    FILE *enc_file_r = fopen("./tests/enc", "rb");
    if (fread(encrypted_r, sizeof(int64_t ), size, enc_file_r) != size)
    {
        printf("Error");
    }
    fclose(enc_file_r);

    int8_t  *decrypted = rsa_decrypt(encrypted_r, 8 * sizeof(message), priv);
    if (!decrypted)
    {
        fprintf(stderr, "Error in decryption!\n");
        return 1;
    }
    printf("\nDecrypted:\n");
    printf("%s\n", decrypted);

    printf("\n");
    free(decrypted);
    return 0;
}