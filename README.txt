
IMPORTANT NOTES BEFORE TESTING ======================================

Passwords for the server side:
    - Enter pass phrase for ./intermediate/private/intermediate.key.pem: lesstopsecretpassword 
Passwords for the client side:
    - Enter pass phrase for <username>-priv.key.pem: <password> (For getcert, this is the given password. For changepw, enter the NEW PASSWORD)

TEST 1: Basic functionality =========================================

Server side: ./test1.sh
Client side: ./test1.sh

This tests the basic functionality of the programs getcert, changepw, 
sendmsg, recvmsg. You can check that the message was delivered properly
by going to server/users/addleness/pending/00001. The message is "Hi 
there!"

TEST 2: Bad cert ====================================================

Server side: ./test2.sh
Client side: ./test2.sh

A user tries to send a message by providing a bad certificate. Notice
that unrosed-cert.pem was modified to contain "BAD CERT STUFF" instead
of the actual certificate. This renders sending the message impossible.

Error message: 
terminate called after throwing an instance of 'std::runtime_error'
  what():  SSL_use_certificate_file() failed


TEST 3: User tries to send a message without having a cert =========== 

Server side: ./test3.sh
Client side: ./test3.sh

A user cannot send a message unless they have their own certificate.

Error message: 
terminate called after throwing an instance of 'std::runtime_error'
  what():  SSL_use_certificate_file() failed
