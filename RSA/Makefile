test: test.o rsa.o   
	gcc -o test test.o rsa.o -Wall

test.o:  test.c
	gcc -c test.c -o test.o -Wall -I ./lib/

rsa.o:  ./lib/rsa.c
	gcc -c ./lib/rsa.c -o ./rsa.o -Wall

clean:
	rm -f *.o test

