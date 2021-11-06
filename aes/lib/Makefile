demo: demo.o aes256.o  
	gcc -o demo demo.o aes256.o -Wall
demo.o: demo.c
	gcc -c demo.c -o demo.o -Wall -I ../lib/


aes256.o:  ../lib/aes256.c
	gcc -c ../lib/aes256.c -o ./aes256.o -Wall

clean:
	rm  *.o demo -f