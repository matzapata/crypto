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
  unsigned char pubFilenameSize = sizeof(char) * (sizeof(PUB_KEY_FILENAME) / sizeof(char) + sizeof(destFolder) / sizeof(char));
  unsigned char privFilenameSize = sizeof(char) * (sizeof(PRIV_KEY_FILENAME) / sizeof(char) + sizeof(destFolder) / sizeof(char));

  char *pubFileName = (char *)malloc(pubFilenameSize);
  strcpy(pubFileName, destFolder);
  strcat(pubFileName, PUB_KEY_FILENAME);

  char *privFileName = (char *)malloc(privFilenameSize);
  strcpy(privFileName, destFolder);
  strcat(privFileName, PRIV_KEY_FILENAME);

  FILE *pubFile = fopen(pubFileName, "wb");
  if (pubFile != NULL)
  {
    fwrite(pub, sizeof(pub), 1, pubFile);
    fclose(pubFile);
  }
  else
  {
    return false;
  }

  FILE *privFile = fopen(privFileName, "wb");
  if (privFile != NULL)
  {
    fwrite(priv, sizeof(priv), 1, privFile);
    fclose(privFile);
  }
  else
  {
    return false;
  }

  // printKeys(pub, priv);

  return true;
}

bool loadKeys(struct public_key_class **pub, struct private_key_class **priv, const char *srcFolder)
{
  *pub = (struct public_key_class *)malloc(1 * sizeof(struct public_key_class));
  *priv = (struct private_key_class *)malloc(1 * sizeof(struct private_key_class));

  // Tamaño de la string que representa el path a las llaves para hacer el malloc
  unsigned char pubFilenameSize = sizeof(char) * (sizeof(PUB_KEY_FILENAME) / sizeof(char) + sizeof(srcFolder) / sizeof(char));
  unsigned char privFilenameSize = sizeof(char) * (sizeof(PRIV_KEY_FILENAME) / sizeof(char) + sizeof(srcFolder) / sizeof(char));

  char *pubFileName = (char *)malloc(pubFilenameSize);
  strcpy(pubFileName, srcFolder);
  strcat(pubFileName, PUB_KEY_FILENAME);

  char *privFileName = (char *)malloc(privFilenameSize);
  strcpy(privFileName, srcFolder);
  strcat(privFileName, PRIV_KEY_FILENAME);

  FILE *pubFile = fopen(pubFileName, "rb");
  if (pubFile != NULL)
  {
    fread(*pub, sizeof(struct public_key_class), 1, pubFile);
    fclose(pubFile);
  }
  else
  {
    return false;
  }

  FILE *privFile = fopen(privFileName, "rb");
  if (privFile != NULL)
  {
    fread(*priv, sizeof(struct private_key_class), 1, privFile);
    fclose(privFile);
  }
  else
  {
    return false;
  }
  return true;
}

void printKeys(struct public_key_class *pub, struct private_key_class *priv)
{
  printf("Public key: %llX:%llX\n", pub->modulus, pub->exponent);
  printf("Private key: %llX:%llX\n", priv->modulus, priv->exponent);
}

/***********************************************************************************************************************************
 *** IMPLEMNTACION DE FUNCIONES PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/*--------------------------------------------------------------------------------------------------------------------------------*/