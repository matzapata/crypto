/*******************************************************************************************************************************/ /**
 *
 * @file	funciones.c
 * @brief   
 * @date
 * @author
 *
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** INCLUDES
 **********************************************************************************************************************************/
#include "funciones.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "rsa.h"

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
bool generateKeys(const char *destFolder)
{
    struct public_key_class pub[1];
    struct private_key_class priv[1];
    rsa_gen_keys(pub, priv, "./primes.txt");

    // Tamaño de la string que representa el path a las llaves para hacer el malloc
    unsigned char pubFilenameSize = sizeof(char)*(sizeof(PUB_KEY_FILENAME)/sizeof(char) + sizeof(destFolder)/sizeof(char)); 
    unsigned char privFilenameSize = sizeof(char)*(sizeof(PRIV_KEY_FILENAME)/sizeof(char) + sizeof(destFolder)/sizeof(char)); 

    char * pubFileName = (char *) malloc(pubFilenameSize);
    strcpy(pubFileName, destFolder);
    strcat(pubFileName, PUB_KEY_FILENAME);

    char * privFileName = (char *) malloc(privFilenameSize);
    strcpy(privFileName, destFolder);
    strcat(privFileName, PRIV_KEY_FILENAME);

    FILE *pubFile = fopen(pubFileName, "wb");
    if (pubFile != NULL)
    {
        fwrite(pub, sizeof(pub), 1, pubFile);
        fclose(pubFile);
    }
    else {
        return false;
    }

    FILE *privFile = fopen(privFileName, "wb");
    if (privFile != NULL)
    {
        fwrite(priv, sizeof(priv), 1, privFile);
        fclose(privFile);
    }
    else {
        return false;
    }

    // printKeys(pub, priv);

    return true;
}

bool loadKeys(struct public_key_class ** pub, struct private_key_class ** priv, const char *srcFolder)
{
    // struct public_key_class pub[1];
    // struct private_key_class priv[1];

    *pub = (struct public_key_class *) malloc(1*sizeof(struct public_key_class));
    *priv = (struct private_key_class *) malloc(1*sizeof(struct private_key_class));

    // Tamaño de la string que representa el path a las llaves para hacer el malloc
    unsigned char pubFilenameSize = sizeof(char)*(sizeof(PUB_KEY_FILENAME)/sizeof(char) + sizeof(srcFolder)/sizeof(char)); 
    unsigned char privFilenameSize = sizeof(char)*(sizeof(PRIV_KEY_FILENAME)/sizeof(char) + sizeof(srcFolder)/sizeof(char)); 

    char * pubFileName = (char *) malloc(pubFilenameSize);
    strcpy(pubFileName, srcFolder);
    strcat(pubFileName, PUB_KEY_FILENAME);

    char * privFileName = (char *) malloc(privFilenameSize);
    strcpy(privFileName, srcFolder);
    strcat(privFileName, PRIV_KEY_FILENAME);

    FILE *pubFile = fopen(pubFileName, "rb");
    if (pubFile != NULL)
    {
        fread(*pub, sizeof(struct public_key_class), 1, pubFile);
        fclose(pubFile);
    }
    else {
        return false;
    }

    FILE *privFile = fopen(privFileName, "rb");
    if (privFile != NULL)
    {
        fread(*priv, sizeof(struct private_key_class), 1, privFile);
        fclose(privFile);
    }
    else {
        return false;
    }
    return true;
}


void printKeys(struct public_key_class * pub, struct private_key_class * priv)
{
    printf("Public key: %llX:%llX\n", pub->modulus, pub->exponent);
    printf("Private key: %llX:%llX\n", priv->modulus, priv->exponent);
}

short rsa_encrypt_file(const char *src_filename, const char *dest_filename, const struct public_key_class *pub)
{
  long long encrypted;
  // long long i = 0;
  long long buf;
  FILE *src_file;
  FILE *dest_file;
  src_file = fopen(src_filename, "rb");
  dest_file = fopen(dest_filename, "wb");

  if (src_file == NULL || dest_file == NULL)
    return -1;
  else
  {
    uint8_t r = 0;
    do
    {
      buf = 0;
      r = fread(&buf, sizeof(long long), 1, src_file);
      if (r != 0)
      {
        if ((encrypted = rsa_modExp(buf, pub->exponent, pub->modulus)) == -1)
        {
          return -1;
        }
        else
        {
          fwrite(&encrypted, sizeof(encrypted), 1, dest_file);
        }
      }
    } while (r != 0);
  }
  fclose(src_file);
  fclose(dest_file);

  return 1;
}

/***********************************************************************************************************************************
 *** IMPLEMNTACION DE FUNCIONES PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/*--------------------------------------------------------------------------------------------------------------------------------*/