#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>
#include "funciones.h"

void displayHelp();
void WriteKeys();
int Encrypt();
int Decrypt();

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        int command = atoi(argv[1]);
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

int Encrypt()
{
    struct public_key_class *pub = NULL;
    struct private_key_class *priv = NULL;
    loadKeys(&pub, &priv, "./keys/");
    printKeys(pub, priv);

    char message[16] = "BA:78:16:BF:8F:";
    int size = 16;

    printf("Original:\n");
    printf("%s\n", message);

    long long *encrypted = rsa_encrypt(message, size, pub);
    if (!encrypted)
    {
        fprintf(stderr, "Error in encryption!\n");
        return 1;
    }

    FILE *enc_file = fopen("./tests/enc", "wb");
    if (fwrite(encrypted, sizeof(long long), size, enc_file) != size)
    {
        printf("File write error.");
    }
    fclose(enc_file);

    free(encrypted);
    return 0;
}

int Decrypt()
{
    struct public_key_class *pub = NULL;
    struct private_key_class *priv = NULL;
    loadKeys(&pub, &priv, "./keys/");
    printKeys(pub, priv);

    // Prueba con output de sha
    char message[16] = "BA:78:16:BF:8F:";
    int size = 16;

    printf("Original:\n");
    printf("%s\n", message);

    // DESENCRIPTAMOS
    long long encrypted_r[16];

    FILE *enc_file_r = fopen("./tests/enc", "rb");
    if (fread(encrypted_r, sizeof(long long), size, enc_file_r) != size)
    {
        printf("Error");
    }
    fclose(enc_file_r);

    char *decrypted = rsa_decrypt(encrypted_r, 8 * sizeof(message), priv);
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