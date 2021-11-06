/*******************************************************************************************************************************//**
 *
 * @file	main.c
 * @brief   Calculo de hash de un archivo con sha256
 * @date
 * @author
 *
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** INCLUDES
 **********************************************************************************************************************************/
#include "functions.h"
#include <stdio.h>
#include <stdlib.h>

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
int main(void) {

    // Ejemplo calculo hash de archivo
    uint8_t * hash;
    
    hash = sha256File("./tests/test.txt");

    printf("hash:\n");
    printHash(hash, SHA256_BLOCK_SIZE);

    free(hash);
    
    return 0;
}


/***********************************************************************************************************************************
 *** IMPLEMNTACION DE FUNCIONES PRIVADAS AL MODULO
 **********************************************************************************************************************************/

/*--------------------------------------------------------------------------------------------------------------------------------*/