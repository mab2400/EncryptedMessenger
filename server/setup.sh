#!/bin/bash

make clean
make

./gen-ca-certs.sh
./gen-server-cert.sh
valgrind ./server
