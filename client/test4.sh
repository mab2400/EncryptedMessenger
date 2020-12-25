#!/bin/bash

./clean.sh

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

mv addleness-cert.pem addleness-temp-cert.pem

valgrind ./getcert 127.0.0.1 unrosed shamed_Dow 

# Generate a new cert 
valgrind ./changepw 127.0.0.1 addleness Cardin_pwns newpass 

mv addleness-cert.pem addleness-new-cert.pem

# Saving the old cert into addleness-cert.pem (ensuring sendmsg will use the old cert instead of new one)
mv addleness-temp-cert.pem addleness-cert.pem 

echo "Hi there!" > hi.txt

echo "unrosed" | valgrind ./sendmsg 127.0.0.1 hi.txt addleness
