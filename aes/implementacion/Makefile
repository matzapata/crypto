encrypt: encrypt.o aes256.o  
	gcc -o encrypt encrypt.o aes256.o -Wall
encrypt.o: encrypt.c
	gcc -c encrypt.c -o encrypt.o -Wall -I ../lib/

decrypt: decrypt.o aes256.o  
	gcc -o decrypt decrypt.o aes256.o -Wall
decrypt.o: decrypt.c
	gcc -c decrypt.c -o decrypt.o -Wall -I ../lib/


aes256.o:  ../lib/aes256.c
	gcc -c ../lib/aes256.c -o ./aes256.o -Wall

clean:
	rm  *.o main encrypt decrypt -f