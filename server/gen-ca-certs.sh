#!/bin/bash

export PASS='topsecretpassword'
export INTER_PASS="lesstopsecretpassword"

#create root certificate
mkdir certs certs/ca
cd certs/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
cd ../..
cp openssl-root.cnf certs/ca/openssl-root.cnf
cd certs/ca
openssl genpkey -out private/ca.key.pem -outform PEM -pass env:PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
chmod 400 private/ca.key.pem
openssl req -config openssl-root.cnf -key private/ca.key.pem -keyform PEM -passin env:PASS -out certs/ca.cert.pem -passout env:PASS -new -x509 -days 7300 -sha256 -extensions v3_ca -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Root Cert'
chmod 444 certs/ca.cert.pem
openssl x509 -noout -text -in certs/ca.cert.pem
cd ../..

#create intermediate certificate
mkdir certs/ca/intermediate
cd certs/ca/intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
cd ../../..
cp openssl-inter2.cnf certs/ca/intermediate/openssl-inter.cnf
cd certs/ca
openssl genpkey -out intermediate/private/intermediate.key.pem -outform PEM -pass env:INTER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
chmod 444 intermediate/private/intermediate.key.pem
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert'
cd ..
openssl ca -batch -config openssl-root.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem -passin env:PASS
chmod 444 intermediate/certs/intermediate.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem
