#!/bin/bash

./clean.sh

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

valgrind ./getcert 127.0.0.1 unrosed shamed_Dow

echo "Hi there!" > hi.txt

echo "BAD CERT STUFF" > unrosed-cert.pem

echo "CHANGED unrosed-cert.pem:"

cat unrosed-cert.pem

echo "addleness" | valgrind ./sendmsg 127.0.0.1 hi.txt unrosed
