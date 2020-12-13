#!/bin/bash

 # - Generate a private key
 # - Create a CSR
 # - Create a client certificate based on that CSR
 # - Verify the client certificate
 # - Verify the entire CA chain (root + intermediate)

echo "[ ca ]
# man ca
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME/rootca/intermediate
certs             = $HOME/rootca/intermediate/certs
crl_dir           = $HOME/rootca/intermediate/crl
new_certs_dir     = $HOME/rootca/intermediate/newcerts
database          = $HOME/rootca/intermediate/index.txt
serial            = $HOME/rootca/intermediate/serial
RANDFILE          = $HOME/rootca/intermediate/private/.rand

# The root key and root certificate.
private_key       = $HOME/rootca/intermediate/private/intermediate.key.pem
certificate       = $HOME/rootca/intermediate/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $HOME/rootca/intermediate/crlnumber
crl               = $HOME/rootca/intermediate/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of man ca.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the ca man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the req tool (man req).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = NY
localityName_default            = New York
0.organizationName_default      = Mia Company
organizationalUnitName_default  = Mia Team
commonName_default              = MiaServer
emailAddress_default            = mbramel9@gmail.com

[ v3_ca ]
# Extensions for a typical CA (man x509v3_config).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (man x509v3_config).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (man x509v3_config).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (man x509v3_config).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ encryption_cert ]
# Extensions for Part (c) certificates (man x509v3_config).
basicConstraints = CA:FALSE
nsComment = "OpenSSL Generated Certificate For Encrypting Files"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = keyEncipherment, dataEncipherment, keyAgreement

[ signing_cert ]
# Extensions for Part (d) certificates (man x509v3_config).
basicConstraints = CA:FALSE
nsComment = "OpenSSL Generated Certificate For Signing Files"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = keyCertSign, digitalSignature, nonRepudiation

[ crl_ext ]
# Extension for CRLs (man x509v3_config).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (man ocsp).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
" >> $HOME/rootca/intermediate/server.cnf

# Generating a Private Key
 cd $HOME/rootca
 openssl genrsa -aes256 \
                -out $HOME/rootca/intermediate/private/server.key.pem 2048
 chmod 400 $HOME/rootca/intermediate/private/server.key.pem

 # Using the private key to create a certificate signing request (CSR).
 openssl req -config $HOME/rootca/intermediate/server.cnf \
             -key $HOME/rootca/intermediate/private/server.key.pem \
             -new -sha256 -out $HOME/rootca/intermediate/csr/server.csr.pem

 # Creating the Certificate based on that CSR.
 openssl ca -config $HOME/rootca/intermediate/server.cnf \
            -extensions server_cert -days 375 -notext -md sha256 \
            -in $HOME/rootca/intermediate/csr/server.csr.pem \
            -out $HOME/rootca/intermediate/certs/server.cert.pem
 chmod 444 $HOME/rootca/intermediate/certs/server.cert.pem

 # Verify the certificate
 openssl x509 -noout -text \
              -in $HOME/rootca/intermediate/certs/server.cert.pem

 # The ca-chain is the root CA plus the intermediate CA.
 openssl verify -CAfile $HOME/rootca/intermediate/certs/ca-chain.cert.pem \
                        $HOME/rootca/intermediate/certs/server.cert.pem

 # Write a random text file to the current directory
 # The client will ask the server for this file later.
 echo "

  ∧＿∧
 ( ･w･)つ━☆・*。
 ⊂　 ノ 　　　・゜+. security is fun
 しーＪ　　　°。+ *

 " > textfile.txt

 # Starting the OpenSSL s_server
 openssl s_server -key $HOME/rootca/intermediate/private/server.key.pem \
                  -cert $HOME/rootca/intermediate/certs/server.cert.pem \
                  -accept 4433 \
                  -HTTP \
