
main: funciones.o main.o rsa.o  
	gcc -o main funciones.o main.o rsa.o -Wall

test: funciones.o test.o rsa.o  
	gcc -o test funciones.o test.o rsa.o -Wall

test.o:  test.c
	gcc -c test.c -o test.o -Wall -I ../lib/

main.o:  main.c
	gcc -c main.c -o main.o -Wall -I ../lib/

funciones.o:  funciones.c 
	gcc -c funciones.c -o funciones.o -Wall -I ../lib/

rsa.o:  ../lib/rsa.c
	gcc -c ../lib/rsa.c -o ./rsa.o -Wall

run: main
	./main
	rm  *.o main -f

clean:
	rm  *.o main -f