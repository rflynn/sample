CFLAGS=-W -Wall -std=c89 -pedantic
LDFLAGS=
sample: sample.o
sample.o: sample.c Makefile
