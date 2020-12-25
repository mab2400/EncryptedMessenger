#!/bin/bash

rm hi.txt
rm addleness-cert.pem
rm addleness-priv.key.pem
rm unrosed-cert.pem
rm unrosed-priv.key.pem

make clean
make

valgrind ./getcert 127.0.0.1 addleness Cardin_pwns

valgrind ./getcert 127.0.0.1 unrosed shamed_Dow

valgrind ./changepw 127.0.0.1 addleness Cardin_pwns newpass

echo "Hi there!" > hi.txt

# rm -rf addleness-cert.pem --> Not sure if I would need to do this, but
# to simulate the different clients being on different machines. Because
# sendmsg will save another copy of addleness-cert.pem and I don't know 
# if the permissions will allow it to overwrite the version which was
# already there

echo "addleness" | valgrind ./sendmsg 127.0.0.1 hi.txt unrosed

valgrind ./recvmsg 127.0.0.1 addleness
