#!/bin/bash
rm -rf ../rootca
make clean
./boilerplate/openssl.sh
./boilerplate/server.sh
./boilerplate/client.sh
