/*******************************************************************************************************************************//**
 *
 * @file		functions.h
 * @brief       Implementacion de funciones para calcular el hash de un archivo con sha256
 * @date
 * @author
 *
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** MODULO
 **********************************************************************************************************************************/
#ifndef MODULE_H
#define MODULE_H_


/***********************************************************************************************************************************
 *** INCLUDES
 **********************************************************************************************************************************/
#include "sha256.h"

/***********************************************************************************************************************************
 *** DEFINES (publicos)
 **********************************************************************************************************************************/

/***********************************************************************************************************************************
 *** MACROS
 **********************************************************************************************************************************/


/***********************************************************************************************************************************
 *** TIPO DE DATOS PUBLICOS
 **********************************************************************************************************************************/


/***********************************************************************************************************************************
 *** VARIABLES GLOBALES (extern)
 **********************************************************************************************************************************/


/***********************************************************************************************************************************
 *** PROTOTIPOS DE FUNCIONES
 **********************************************************************************************************************************/
/*
 * Calcula el hash de un archivo pasado como arg y lo devuelve 
*/
uint8_t * sha256File(const char * filename);
void printHash(const uint8_t * hash, const size_t size);

/***********************************************************************************************************************************
 *** FIN DEL MODULO
 **********************************************************************************************************************************/

#endif /* MODULE_H_ */