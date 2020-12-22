#!/bin/bash

export CLIENT_PASS="topsecretclientpassword"

# generate web client certificate
cd certs/ca
openssl genpkey -out client/private/client.key.pem -outform PEM -pass env:CLIENT_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
chmod 400 client/private/client.key.pem

# Using the private key to create a certificate signing request (CSR).
openssl req -config intermediate/openssl-inter2.cnf \
	    -passin env:CLIENT_PASS \
	    -key client/private/client.key.pem \
            -new -sha256 -out client/csr/client.csr.pem \
	    -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=ClientCSRName'

