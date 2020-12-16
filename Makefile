CC=g++
CXXFLAGS=-g -Wall -std=c++17
LDLIBS=-lssl -lcrypto

ALL_PROGRAMS=server getcert changepw sendmsg recvmsg client

.PHONY: default
default: $(ALL_PROGRAMS)

server:

getcert:

changepw:

sendmsg:

recvmsg:

client:

.PHONY: clean
clean:
	rm -f a.out core *.o $(ALL_PROGRAMS)
