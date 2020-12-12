Mia Bramel
mab2400
Security Assignment #2

===== D E S C R I P T I O N S =====

> openssl.sh
    - Removes any existing directory structure from previous test run
    - Builds the entire directory structure from scratch
    - Creates the Root and Intermediate certificates
    - Verifies the Root and Intermediate certificates
    - Creates the CA Chain file

> server.sh
    - Creates the Server certificate
    - Verifies the Server certificate
    - Verifies the CA chain
    - Writes a textfile.txt into the current directory
    - Runs the server (s_server command) via the -HTTP option on Port 4433.

> client.sh
    - Connects to the server and sends a GET request to the server for the
        file called "textfile.txt"

> partc.sh
    - Creates a certificate that is suitable for encrypting files.
    - In the config file openssl.cnf, I created my own extension [ encryption_cert ]
        which has the following extensions within it:
        - keyEncipherment (allows the certificate to encrypt a symmetric key)
        - dataEncipherment (allows the certificate to encrypt/decrypt application data)
        - keyAgreement (allows the certificate to create a symmetric key)
    - Source: OpenSSL Manpages, https://superuser.com/questions/738612/openssl-ca-keyusage-extension

> partd.sh
    - Creates a certificate that is suitable for signing files.
    - In the config file openssl.cnf, I created my own extension [ signing_cert ]
        which has the following extensions within it:
        - keyCertsign (allows the public key to verify certificate signatures)
        - digitalSignature (allows the certificate to apply a digital signature)
        - nonRepudiation (same as digitalSignature but the public key can be used for
            non-repudiation purposes)
    - Source: OpenSSL Manpages, https://superuser.com/questions/738612/openssl-ca-keyusage-extension


===== S C R I P T S =====


    NOTE FOR THE TAS:
        - You can just hit "Enter" when entering the fields, I set up default values for this.
            Although if you wish to enter your own values in the fields, that's fine too.


    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 1, Parts A and B:

    ----------------------------------- SERVER CERTIFICATE ------------------------------------
    PART A (run in one window)
        - ./openssl.sh
        - ./server.sh

    ---------------------------- CLIENT CERTIFICATE AND TEXT FILE  ----------------------------
    PART B (run in a different window)
        - ./client.sh
    ===========================================================================================




    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 2: Certificate Suitable for Encrypting Files
        - ./openssl.sh
        - ./partc.sh
    ===========================================================================================




    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 3: Certificate Suitable for Signing Files
        - ./openssl.sh
        - ./partd.sh
    ===========================================================================================



===== E R R O R    T E S T I N G =====


    NOTE FOR THE TAS:
        - Sometimes the error message is buried within the output and requires you to scroll
            up to find it!


    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 4: Error Code 10
        - Run ./openssl.sh and then ./server.sh in one window
        - Run ./error_code_10.sh in another window

    NOTES:
        - This script returns the following error:
            error 10 at 0 depth lookup:certificate has expired
        - Creates an expired client certificate, which cannot be properly verified.
    ===========================================================================================



    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 5: Error Codes 20 and 21
        - Run ./openssl.sh and then ./server.sh in one window
        - Run ./error_codes_20_21.sh in another window

    NOTES:
        - This script returns the following errors:
            verify error:num=20:unable to get local issuer certificate
            Verify return code: 21 (unable to verify the first certificate)
        - To generate these errors, I removed the -CAfile option when calling s_client. This
            option tells openssl where the root CA file is, so when I remove it, openssl cannot
            access and verify the issuer certificate.
        - These same errors can also be generated if I delete the CA chain cert.
    ===========================================================================================



    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 6: Error Code 9
        - Run ./openssl.sh and then ./server.sh in one window
        - Run ./error_code_9.sh in another window

    NOTES:
        - This script returns the following error:
            error 9 at 0 depth lookup:certificate is not yet valid
        - Creates a client certificate, which is set to become
            valid in 2021 (Not Before = 2021 Jan 1). Therefore, it cannot be properly verified.
    ===========================================================================================



    ===========================================================================================
    INSTRUCTIONS FOR SCRIPT 7: Error Code 26
        - Run ./openssl.sh and then ./error_code_26.sh in one window
        - Run ./client.sh in another window

    NOTES:
        - This script returns the following error:
            Verify return code: 26 (unsupported certificate purpose)
        - Creates a server certificate, but uses the usr_cert extension, therefore not giving
            the server the ability to serve files. Connection to it via a client will be
            unsuccessful.
    ===========================================================================================
