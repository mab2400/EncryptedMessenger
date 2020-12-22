#!/bin/bash

# Take the CSR sent by the server and use it to create and sign a certificate 

username = $1

cd certs/ca
openssl ca -config ../../openssl-inter.cnf \
           -extensions encryption_cert -notext -md sha256 \
           -in ../../users/$1/csr \
           -out ../../users/$1/cert
