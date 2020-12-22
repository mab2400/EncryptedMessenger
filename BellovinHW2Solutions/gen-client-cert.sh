#!/bin/bash

# Take the CSR sent by the server (getcert_csr.pem) and use it to create and sign a certificate 
cd certs/ca
openssl ca -config ../../openssl-inter.cnf \
           -extensions encryption_cert -notext -md sha256 \
           -in ../../getcert_csr.pem \
           -out ../../getcert.cert.pem
