To run the programs:
1) ./setup.sh
2) ./server
3) [coming soon] Connecting the client to the server


========= Or equivalently (setup.sh does most of this for you) =======

Setting up the CA, Intermediate Cert, and Server Cert (I believe these should be part of code installation script):
1) ./boilerplate/openssl.sh
2) ./boilerplate/server.sh

Setting up the Client Cert:
3) ./client.sh
    - When prompted to "Enter PEM pass phrase":

Running the server:
4) ./server
    - When prompted to "Enter PEM pass phrase":

[coming soon] Connecting the client to the server:

