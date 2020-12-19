#!/bin/bash
rm -rf ../rootca
make clean
make
./BellovinHW2Solutions/gen-ca-certs.sh
./BellovinHW2Solutions/gen-server-cert.sh
./BellovinHW2Solutions/gen-client-key.sh
valgrind ./server
