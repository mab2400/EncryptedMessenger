CC=g++
CXXFLAGS=-g -Wall -std=c++17

ALL_PROGRAMS=server getcert changepw sendmsg recvmsg

.PHONY: default
default: $(ALL_PROGRAMS)

server:

getcert:

changepw:

sendmsg:

recvmsg:

.PHONY: clean
clean:
	rm -f a.out core *.o $(ALL_PROGRAMS)
