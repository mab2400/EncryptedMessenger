#!/bin/bash

rm -rf certs
rm -rf users

make clean
make

mkdir users
cd users
# TODO: make all of the user directories
mkdir user1 user2
echo "pass1" > user1/password.txt
echo "pass2" > user2/password.txt

cd ..

./gen-ca-certs.sh
./gen-server-cert.sh
valgrind ./server
