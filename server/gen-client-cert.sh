#!/bin/bash

# Take the CSR sent by the server and use it to create and sign a certificate 
export INTER_PASS=$2

openssl ca -config openssl-inter.cnf \
           -extensions usr_cert -notext -md sha256 \
	   -passin env:INTER_PASS \
           -in users/$1/csr_temp.pem \
           -out users/$1/cert
