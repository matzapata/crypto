
# Problemas
Aes -> falta resolver problema de padding. Caso es que fuente no es exactamente de 16 bytes utiles

# Rutinas

## Enviar archivo a contacto
Genero clave random para AES
Encripto archivo con AES
Encripto clave publica contacto con RSA
Envio archivo encriptado y clave encriptada

## Firma digital
Calculo sha256 del archivo
Encripto output sha256 con clave privada firmante
Envio archivo y resultado paso anterior

## Verificacion firma
Calculo sha256 del archivo
Desencripto output sha256 con clave publica firmante


