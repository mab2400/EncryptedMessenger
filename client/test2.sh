#!/bin/bash

rm hi.txt
rm .newmsg.txt
rm newmsg.txt
rm addleness-both.pem
rm addleness-cert.pem
rm addleness-priv.key.pem
rm addleness-new-cert.pem
rm unrosed-both.pem
rm unrosed-cert.pem
rm unrosed-priv.key.pem

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

valgrind ./getcert 127.0.0.1 unrosed shamed_Dow

echo "Hi there!" > hi.txt

echo "BAD CERT STUFF" > unrosed-cert.pem

echo "CHANGED unrosed-cert.pem:"

cat unrosed-cert.pem

echo "addleness" | valgrind ./sendmsg 127.0.0.1 hi.txt unrosed
