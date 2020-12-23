CC=g++
CXXFLAGS=-g -Wall -std=c++17
LDLIBS=-lssl -lcrypto -lstdc++fs
	

ALL_PROGRAMS=getcert changepw sendmsg recvmsg 

.PHONY: default
default: $(ALL_PROGRAMS)

getcert:

changepw:

sendmsg: ../common.hpp client-common.hpp

recvmsg: ../common.hpp client-common.hpp

.PHONY: clean
clean:
	rm -f a.out core *.o $(ALL_PROGRAMS)
