test_simple: test_simple.o rsa.o   
	gcc -o test_simple test_simple.o rsa.o -Wall

test_simple.o:  test_simple.c
	gcc -c test_simple.c -o test_simple.o -Wall -I ./lib/

rsa.o:  ./lib/rsa.c
	gcc -c ./lib/rsa.c -o ./rsa.o -Wall

clean:
	rm -f *.o test_simple

