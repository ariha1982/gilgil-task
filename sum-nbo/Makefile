#Makefile
all: sum-nbo

sum-nbo: sum-nbo.o
	gcc -o sum-nbo sum-nbo.o
#	gcc -o sum-nbo sum-nbo.o -lws2_32

sum-nbo.o: sum-nbo.c
	gcc -c sum-nbo.c

