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
char *msg_fname;
char *sender;

/* one GET request to get recver's certificate from server */
void GET_recver_cert(SSL_CTX *ctx, std::string recver)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "GET /sendmsg/1 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "Recver: %s\r\n"
                               "\r\n",
                               sender, recver.c_str());
    
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

    // get recver cert and save it
    std::string fname = recver + "-cert";
    BIO_read_to_file_until_close(server, fname);
    std::cerr << "Recved and saved recver cert in " << fname << std::endl;

    cleanup(server, ssl);
}

/* one POST request to send encrypted msg to server */
void POST_msg(SSL_CTX *ctx, std::string recver)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    std::string msg = read_file_into_string(msg_fname);
    int content_length = msg.length();

    // TODO: encrypt the msg using recver-cert

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "POST /sendmsg/2 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "Recver: %s\r\n"
                               "Content-Length: %d\r\n"
                               "\r\n",
                               sender, recver.c_str(), content_length);

    // send first line + headers to server
    BIO_mywrite(server, req);

    // send msg to the server
    BIO_mywrite(server, msg);

    cleanup(server, ssl);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <hostname> <msg-filename> <sender-username>" << std::endl;
        exit(1);
    }

    // global vars
    hostname = argv[1];
    msg_fname = argv[2];
    sender = argv[3];
    
    ssl_load();
    SSL_CTX *ctx = create_ssl_ctx();

    std::cout << "Enter receivers, one per line, then Ctrl-D:" << std::endl;
    std::vector<std::string> recvers;
    std::string line;
    while (std::getline(std::cin, line)) {
        recvers.push_back(line);
    }

    std::cout << std::endl;

    for (std::string& recver : recvers) {
        GET_recver_cert(ctx, recver);
        POST_msg(ctx, recver);
    }

    SSL_CTX_free(ctx); 
    return 0;
}
