test: test.c aes.c aes.h
	rm test -f
	gcc -o test test.c aes.c -Wall

aes: aes.c aes.h
	rm aes.o -f
	gcc -o aes.o -c aes.c -Wall

clean:
	rm  *.o test -f