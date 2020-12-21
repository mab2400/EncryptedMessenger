#!/bin/bash

# generate web client public/private key pair 

cd certs/ca

# Get the private and public keys
openssl genrsa -out client/client-priv.key.pem -aes256 2048 
openssl rsa -in client/client-priv.key.pem -pubout -out client/client-pub.key.pem -aes256 2048 
#chmod 400 client/client-priv.key.pem
#chmod 400 client/client-pub.key.pem

# Using the private key to create a certificate signing request (CSR).
openssl req -config intermediate/openssl-inter2.cnf \
            -new -sha256 -out intermediate/csr/client.csr.pem \
            -key client/client-priv.key.pem \

chmod 400 client/client-priv.key.pem
chmod 400 client/client-pub.key.pem
