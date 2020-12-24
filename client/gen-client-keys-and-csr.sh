#!/bin/bash

# generate web client public/private key pair 
export COMMON_NAME=$1
export CLIENT_PASS=$2

# Get the private and public keys
openssl genrsa -passout env:CLIENT_PASS -out $1-priv.key.pem -aes256 2048 

openssl rsa -passin env:CLIENT_PASS -in $1-priv.key.pem -pubout -out $1-pub.key.pem -aes256 2048 

#chmod 400 client/client-priv.key.pem
#chmod 400 client/client-pub.key.pem

# Using the private key to create a certificate signing request (CSR).
#openssl req -config ../openssl-inter.cnf \
openssl req -new -sha256 -out $1.csr.pem \
            -key $1-priv.key.pem \
	    -passout env:CLIENT_PASS \
	    -subj "/C=US/ST=New York/O=COMS4181 Hw2/CN={$1}"
