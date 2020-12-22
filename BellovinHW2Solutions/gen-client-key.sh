#!/bin/bash

# generate web client public/private key pair 
export COMMON_NAME=$1
export CLIENT_PASS=$2

cd certs/ca

# Get the private and public keys
openssl genrsa -passout env:CLIENT_PASS -out client/client-priv.key.pem -aes256 2048 

openssl rsa -passin env:CLIENT_PASS -in client/client-priv.key.pem -pubout -out client/client-pub.key.pem -aes256 2048 

#chmod 400 client/client-priv.key.pem
#chmod 400 client/client-pub.key.pem
echo "/C=US/ST=New York/O=COMS4181 Hw2/CN={$1}"

# Using the private key to create a certificate signing request (CSR).
openssl req -config intermediate/openssl-inter2.cnf \
            -new -sha256 -out intermediate/csr/client.csr.pem \
            -key client/client-priv.key.pem \
	    -passout env:CLIENT_PASS \
	    -subj "/C=US/ST=New York/O=COMS4181 Hw2/CN={$1}"
