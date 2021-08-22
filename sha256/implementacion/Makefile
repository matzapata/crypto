
main: functions.o main.o sha256.o  
	gcc -o main functions.o main.o sha256.o -Wall

main.o:  main.c
	gcc -c main.c -o main.o -Wall -I ../lib/

functions.o:  functions.c
	gcc -c functions.c -o functions.o -Wall -I ../lib/

sha256.o:  ../lib/sha256.c
	gcc -c ../lib/sha256.c -o ./sha256.o -Wall

run: main
	./main
	rm  *.o main -f

clean:
	rm  *.o main -f