#!/bin/bash

rm hi.txt
rm addleness-cert.pem
rm addleness-priv.key.pem
rm unrosed-cert.pem
rm unrosed-priv.key.pem

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

echo "Hi there!" > hi.txt

echo "addleness" | valgrind ./sendmsg 127.0.0.1 hi.txt unrosed
