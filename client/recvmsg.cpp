#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "../common.hpp"
#include "client-common.hpp"

char *hostname;
char *recver;

/* one GET request to get one msg from server */
void GET_msg(SSL_CTX *ctx)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "GET /recvmsg HTTP/1.0\r\n"
                               "Recver: %s\r\n"
                               "\r\n",
                               recver);
    
    // send request to server
    BIO_mywrite(server, req);
    std::cerr << "Sent:" << std::endl << req;

    // read first line
    std::string line;
    if (BIO_mygets(server, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");
    
    std::cerr << "Server said:" << std::endl << line << std::endl;
    
    if (line.find("200 OK") == std::string::npos)
        throw std::runtime_error("Not 200 OK");

    BIO_skip_headers(server);

    char *buf;
    BIO *mem = create_mem_bio();
    BIO_to_BIO_until_close(server, mem);
    BIO_get_mem_data(mem, &buf);

    // TODO: decrypt message

    std::cout << "Received msg: " << std::endl << buf << std::endl;

    BIO_free(mem);
    cleanup(server, ssl);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <hostname> <recver>" << std::endl;
        exit(1);
    }

    // global vars
    hostname = argv[1];
    recver = argv[2];
    
    ssl_load();
    SSL_CTX *ctx = create_ssl_ctx();
    
    GET_msg(ctx);

    SSL_CTX_free(ctx); 
    return 0;
}
