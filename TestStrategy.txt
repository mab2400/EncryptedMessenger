Security Final Project
Mia Bramel, Lucie le Blanc, Michael Jan
12/25/20


=====================================================================
TEST 1: Basic functionality =========================================
=====================================================================

Server side: ./test.sh
Client side: ./test1.sh

This tests the basic functionality of the programs getcert, changepw, 
sendmsg, recvmsg. You can check that the message was delivered properly
by going to server/users/addleness/pending/00001. The message is "Hi 
there!"

=====================================================================
TEST 2: Bad cert ====================================================
=====================================================================

Server side: ./test.sh
Client side: ./test2.sh

A user tries to send a message by providing a bad certificate. Notice
that unrosed-cert.pem was modified to contain "BAD CERT STUFF" instead
of the actual certificate. This renders sending the message impossible.

Error message: 
terminate called after throwing an instance of 'std::runtime_error'
  what():  SSL_use_certificate_file() failed

=====================================================================
TEST 3: User tries to send a message without having a cert ========== 
=====================================================================

Server side: ./test.sh
Client side: ./test3.sh

A user cannot send a message unless they have their own certificate.

Error message: 
terminate called after throwing an instance of 'std::runtime_error'
  what():  SSL_use_certificate_file() failed

=====================================================================
TEST 4: User tries to send a message with an old cert =============== 
=====================================================================

Server side: ./test.sh
Client side: ./test4.sh

A user cannot send a message unless are using the correct cert version.

Error message: 
terminate called after throwing an instance of 'std::runtime_error'
  what():  SSL_use_PrivateKey_file() failed

=====================================================================
TEST 5: User enters a username that is not one of the given usernames
=====================================================================

Server side: ./test.sh
Client side: ./test5.sh

A user must have one of the usernames given in users.txt.

Error message: 
HTTP/1.0 400 Bad Request

Error: Invalid username

=====================================================================
TEST 6: User enters the wrong password to getcert =================== 
=====================================================================

Server side: ./test.sh
Client side: ./test6.sh

Error message: 
HTTP/1.0 400 Bad Request

Error: Incorrect password 

=====================================================================
TEST 7: User enters the wrong password to changepw ================== 
=====================================================================

Server side: ./test.sh
Client side: ./test7.sh

Error message: 
HTTP/1.0 400 Bad Request

Error: Incorrect password 
