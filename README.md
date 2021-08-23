
# Procesos

## Firma digital

Genera un archivo como el siguiente
{
    hash: "ajhhalabsal", (resultado sha256 sobre content{})
    public_key: "lahkjsbas:ajkhs", (Firma del firmante),
    certificate: "shashabs" (Ente certificante firma public key)
    content: {
        timestamp: "10/10/10-15:20"
        body: "............."
    }
}

## Encriptacion asimetrica
Se recibe por usb o bt el archivo a encriptar
Se calcula el hash y se lo muestra por pantalla para que lo verifique el usuario y confirme o cancele 
Se recibe por usb o bt la clave publica con la que se quiere firmar
Se muestra por pantalla para que lo confirme el usuario
Se encripta con RSA
Se devuelve el archivo encriptado

## Almacenamiento de datos
Generacion de llave simetrica
Almacenamiento de dicha clave segura
Encriptacion de archivo con AES y almacenamiento en memoria interna (SD)
Se devuelve el archivo encriptado por usb o bt


## Visualizacion temporal de data
Enviamos data json encriptada con clave que es conformada con una variable tiempo en juego,  
{

}
