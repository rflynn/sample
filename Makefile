CFLAGS=-W -Wall -std=gnu99 -pedantic
LDFLAGS=
sample: sample.o
sample.o: sample.c Makefile
