#!/bin/bash

export CLIENT_PASS="topsecretclientpassword"

# generate web client certificate
cd certs/ca
openssl genpkey -out client/private/client.key.pem -outform PEM -pass env:CLIENT_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
pwd
chmod 400 client/private/client.key.pem
