To run the programs:
1) ./setup.sh
2) In another window, valgrind ./client 


========= Or equivalently (setup.sh does most of this for you) =======

Setting up the CA, Intermediate Cert, and Server Cert (I believe these should be part of code installation script):
1) ./boilerplate/openssl.sh
2) ./boilerplate/server.sh

Setting up the Client Cert:
3) ./client.sh

Running the server:
4) valgrind ./server

Connecting the client to the server [in another window]:
5) valgrind ./client

