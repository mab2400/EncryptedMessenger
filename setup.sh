#!/bin/bash
rm -rf ../rootca
make clean
make
./boilerplate/openssl.sh
./boilerplate/server.sh
./boilerplate/client.sh
sudo ./server
