#!/bin/bash

# generate web client public/private key pair 
export COMMON_NAME=$1
export CLIENT_PASS=$2

# Get the private and public keys
openssl genrsa -out $1-priv.key.pem 2048 

openssl rsa -in $1-priv.key.pem -pubout -out $1-pub.key.pem  2048 

chmod 600 $1-priv.key.pem

# Using the private key to create a certificate signing request (CSR).
openssl req -new -sha256 -out $1.csr.pem \
            -key $1-priv.key.pem \
	    -subj "/C=US/ST=New York/O=COMS4181 Hw2/CN={$1}"
