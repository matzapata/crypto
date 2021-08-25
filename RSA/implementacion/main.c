/*******************************************************************************************************************************/ /**
 *
 * @file	main.c
 * @brief   Implementacion RSA para encriptacion asimetrica
 * @date
 * @author
 *
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** INCLUDES
 **********************************************************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rsa.h"
#include "funciones.h"

/***********************************************************************************************************************************
 *** DEFINES PRIVADOS AL MODULO
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** MACROS PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** TIPOS DE DATOS PRIVADOS AL MODULO
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** TABLAS PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** VARIABLES GLOBALES PUBLICAS
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** VARIABLES GLOBLES PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** PROTOTIPO DE FUNCIONES PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
*** CONFIGURACION DE ERRORES
**********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** IMPLEMENTACION DE FUNCIONES PUBLICAS
 **********************************************************************************************************************************/
int main(void)
{
    // generateKeys("./keys/");
    // // Generamos las llaves
    struct public_key_class * pub = NULL;
    struct private_key_class  * priv = NULL;
    loadKeys(&pub, &priv, "./keys/");
    printKeys(pub, priv);

    rsa_encrypt_file("./tests/test.txt", "./tests/test.enc", pub);
    // // Obtenemos el mesnaje a encriptar
    // // En este caso con el resultador del hash de un archivo
    // char message[] = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";

    // // Encriptamos
    // long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
    // if (!encrypted)
    // {
    //     fprintf(stderr, "Error in encryption!\n");
    //     return 1;
    // }

    // // Desencriptamos
    // char *decrypted = rsa_decrypt(encrypted, 8 * sizeof(message), priv);
    // if (!decrypted)
    // {
    //     fprintf(stderr, "Error in decryption!\n");
    //     return 1;
    // }
    // printf("\nDecrypted:\n");
    // printf("%s\n", decrypted);

    free(pub);
    free(priv);
    // free(encrypted);
    // free(decrypted);

    printf("\n");

    return 0;
}

/***********************************************************************************************************************************
 *** IMPLEMNTACION DE FUNCIONES PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/*--------------------------------------------------------------------------------------------------------------------------------*/