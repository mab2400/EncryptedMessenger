#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export INTER_PASS="lesstopsecretpassword"

# generate web server certificate
cd certs/ca
# generate web server certificate
mkdir server client server/private client/private server/certs client/certs server/csr client/csr other other/private other/csr other/certs
openssl genpkey -out server/private/server.key.pem -outform PEM -pass env:SERVER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
chmod 400 server/private/server.key.pem
openssl req -config intermediate/openssl-inter.cnf -key server/private/server.key.pem -keyform PEM -passin env:SERVER_PASS -out server/csr/server.csr.pem -passout env:SERVER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220.columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions server_cert -days 365 -notext -md sha256 -in server/csr/server.csr.pem -out server/certs/server.cert.pem -passin env:INTER_PASS
chmod 444 server/certs/server.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem server/certs/server.cert.pem
cp intermediate/certs/ca-chain.cert.pem server/certs/ca-chain.cert.pem

