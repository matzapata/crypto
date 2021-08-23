
main: funciones.o main.o rsa.o  
	gcc -o main funciones.o main.o rsa.o -Wall

main.o:  main.c
	gcc -c main.c -o main.o -Wall -I ../lib/

functions.o:  funciones.c 
	gcc -c funciones.c -o funciones.o -Wall -I ../lib/

rsa.o:  ../lib/rsa.c
	gcc -c ../lib/rsa.c -o ./rsa.o -Wall

run: main
	./main
	rm  *.o main -f

clean:
	rm  *.o main -f