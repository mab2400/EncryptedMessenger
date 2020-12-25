#!/bin/bash

./clean.sh 

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

valgrind ./getcert 127.0.0.1 unrosed shamed_Dow

valgrind ./changepw 127.0.0.1 addleness Cardin_pwns newpass

echo "Hi there!" > hi.txt

echo "addleness" | valgrind ./sendmsg 127.0.0.1 hi.txt unrosed

valgrind ./recvmsg 127.0.0.1 addleness
