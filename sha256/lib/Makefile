
test: test.o sha256.o  
	gcc -o test test.o sha256.o -Wall

test.o:  test.c
	gcc -c test.c -o test.o -Wall -I ../lib/

sha256.o:  sha256.c
	gcc -c sha256.c -o sha256.o -Wall

clean:
	rm  *.o test -f