#!/bin/bash
./delete.sh

# Creating a directory rootca to hold the keys and certificates.
mkdir $HOME/rootca
cd $HOME/rootca
mkdir $HOME/rootca/certs $HOME/rootca/crl $HOME/rootca/newcerts $HOME/rootca/private
chmod 700 $HOME/rootca/private

# index.txt and serial keep track of signed certificates.
touch $HOME/rootca/index.txt
echo 1000 > $HOME/rootca/serial

# Copy the root CA configuration file from the Appendix to rootca/openssl.cnf
echo "
[ ca ]
# man ca
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $HOME/rootca
certs             = $HOME/rootca/certs
crl_dir           = $HOME/rootca/crl
new_certs_dir     = $HOME/rootca/newcerts
database          = $HOME/rootca/index.txt
serial            = $HOME/rootca/serial
RANDFILE          = $HOME/rootca/private/.rand

# The root key and root certificate.
private_key       = $HOME/rootca/private/ca.key.pem
certificate       = $HOME/rootca/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = $HOME/rootca/crlnumber
crl               = $HOME/rootca/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

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
commonName_default              = Mia1
emailAddress_default            = mab2400@columbia.edu

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
" >> $HOME/rootca/openssl.cnf

# Create the root key.
openssl genrsa -aes256 \
               -out $HOME/rootca/private/ca.key.pem \
               4096

chmod 400 $HOME/rootca/private/ca.key.pem

# Create the root certificate.
openssl req -config $HOME/rootca/openssl.cnf \
            -key $HOME/rootca/private/ca.key.pem \
            -new -x509 -days 7300 -sha256 -extensions v3_ca \
            -out $HOME/rootca/certs/ca.cert.pem

chmod 444 $HOME/rootca/certs/ca.cert.pem

# Verify the root certificate.
openssl x509 -noout -text -in $HOME/rootca/certs/ca.cert.pem

# Create the intermediate pair
# The root CA signs the intermediate certificate, creating a chain of trust.
# Prepare the directory
mkdir $HOME/rootca/intermediate
cd $HOME/rootca/intermediate
mkdir $HOME/rootca/intermediate/certs $HOME/rootca/intermediate/crl $HOME/rootca/intermediate/csr $HOME/rootca/intermediate/newcerts $HOME/rootca/intermediate/private
chmod 700 $HOME/rootca/intermediate/private
touch $HOME/rootca/intermediate/index.txt
echo 1000 > $HOME/rootca/intermediate/serial

# Adding a crlnumber file to keep track of certificate revocation lists.
echo 1000 > $HOME/rootca/intermediate/crlnumber

# Copy the intermediate CA configuration file from the Appendix to openssl.cnf.
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
commonName_default              = Mia2
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
" >> $HOME/rootca/intermediate/openssl.cnf

# Create the intermediate key
# Currently in rootca/intermediate. Need to move back to rootca.
cd ../
openssl genrsa -aes256 \
               -out $HOME/rootca/intermediate/private/intermediate.key.pem \
               4096
chmod 400 $HOME/rootca/intermediate/private/intermediate.key.pem

# Create the intermediate certificate
openssl req -config $HOME/rootca/intermediate/openssl.cnf -new -sha256 \
            -key $HOME/rootca/intermediate/private/intermediate.key.pem \
            -out $HOME/rootca/intermediate/csr/intermediate.csr.pem

openssl ca -config $HOME/rootca/openssl.cnf -extensions v3_intermediate_ca \
           -days 3650 -notext -md sha256 \
           -in $HOME/rootca/intermediate/csr/intermediate.csr.pem \
           -out $HOME/rootca/intermediate/certs/intermediate.cert.pem

chmod 444 $HOME/rootca/intermediate/certs/intermediate.cert.pem

# Verify the Intermediate Certificate
openssl x509 -noout -text \
             -in $HOME/rootca/intermediate/certs/intermediate.cert.pem

openssl verify -CAfile $HOME/rootca/certs/ca.cert.pem \
      $HOME/rootca/intermediate/certs/intermediate.cert.pem

# Create the certificate chain file
cat $HOME/rootca/intermediate/certs/intermediate.cert.pem \
      $HOME/rootca/certs/ca.cert.pem > $HOME/rootca/intermediate/certs/ca-chain.cert.pem

chmod 444 $HOME/rootca/intermediate/certs/ca-chain.cert.pem

