CC=g++
CXXFLAGS=-g -Wall -std=c++17
LDLIBS=-lssl -lcrypto -lstdc++fs -lcrypt

ALL_PROGRAMS=server 

.PHONY: default
default: $(ALL_PROGRAMS)

server: ../common.hpp

.PHONY: clean
clean:
	rm -f a.out core *.o $(ALL_PROGRAMS)
