#!/bin/bash

rm -rf certs
rm -rf users

make clean
make

mkdir users

./gen-ca-certs.sh
./gen-server-cert.sh
valgrind ./server
