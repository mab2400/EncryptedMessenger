#!/bin/bash

./clean.sh 

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

valgrind ./changepw 127.0.0.1 addleness wrong_password newpass
