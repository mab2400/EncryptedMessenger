CC=g++
CXXFLAGS=-g -Wall -std=c++17
LDLIBS=-lssl -lcrypto -lstdc++fs
	

ALL_PROGRAMS=server 

.PHONY: default
default: $(ALL_PROGRAMS)

server:

.PHONY: clean
clean:
	rm -f a.out core *.o $(ALL_PROGRAMS)
