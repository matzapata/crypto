
demo: demo.c aes256.c aes256.h
	gcc -o demo demo.c aes256.c

encrypt: encrypt.o aes256.o aes256.h
	gcc -o encrypt encrypt.c aes256.c

decrypt: decrypt.c aes256.c aes256.h
	gcc -o decrypt decrypt.c aes256.c

clean:
	rm -f encrypt decrypt demo *.o