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

char *hostname;
char *fname;
char *sender;

void ssl_load()
{
    // load ssl algos and error strings
    SSL_library_init();
    SSL_load_error_strings();
}

SSL_CTX *create_ssl_ctx()
{
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    SSL_CTX_set_default_verify_dir(ctx);
    /* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
    // Do we have to write this ourselves?
    // int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

BIO *myssl_connect(char *hostname, int port, SSL_CTX *ssl_ctx)
{
    struct sockaddr_in sin;
    int sock;
    struct hostent *he;
    int err; char *s;
    SSL *ssl;

    ssl = SSL_new(ssl_ctx);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    bzero(&sin, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    he = gethostbyname(hostname);
    memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
        perror("connect");
        exit(1);
    }

    SSL_set_fd(ssl, sock);
    BIO *sbio;
    sbio=BIO_new(BIO_s_socket());
    BIO_set_fd(sbio, sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    BIO *buf_io;
    BIO *ssl_bio;

    buf_io = BIO_new(BIO_f_buffer()); /* buf_io is type BIO * */
    ssl_bio = BIO_new(BIO_f_ssl());   /* ssl_bio is type BIO * */
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_io, ssl_bio);

    err = SSL_connect(ssl); /* ssl is type SSL * */
    if (SSL_connect(ssl) != 1) {
        switch (SSL_get_error(ssl, err)) {
            case SSL_ERROR_NONE: s=(char *) "SSL_ERROR_NONE"; break;
            case SSL_ERROR_ZERO_RETURN: s=(char *) "SSL_ERROR_ZERO_RETURN"; break;
            case SSL_ERROR_WANT_READ: s=(char *) "SSL_ERROR_WANT_READ"; break;
            case SSL_ERROR_WANT_WRITE: s=(char *) "SSL_ERROR_WANT_WRITE"; break;
            case SSL_ERROR_WANT_CONNECT: s=(char *) "SSL_ERROR_WANT_CONNECT"; break;
            case SSL_ERROR_WANT_ACCEPT: s=(char *) "SSL_ERROR_WANT_ACCEPT"; break;
            case SSL_ERROR_WANT_X509_LOOKUP: s=(char *) "SSL_ERROR_WANT_X509_LOOKUP"; break;
            case SSL_ERROR_WANT_ASYNC: s=(char *) "SSL_ERROR_WANT_ASYNC"; break;
            case SSL_ERROR_WANT_ASYNC_JOB: s=(char *) "SSL_ERROR_WANT_ASYNC_JOB"; break;
            case SSL_ERROR_SYSCALL: s=(char *) "SSL_ERROR_SYSCALL"; break;
            case SSL_ERROR_SSL: s=(char *) "SSL_ERROR_SSL"; break;
        }
        fprintf(stderr, "SSL error: %s\n", s);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    return buf_io;
}

/* one GET request to get recver's certificate from server */
void GET_recver_cert(SSL_CTX *ctx, std::string recver)
{
    BIO *server = myssl_connect(hostname, CERT_PORT, ctx);

    char req[1000];
    snprintf(req, sizeof(req), "GET /sendmsg/1 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "Recver: %s\r\n"
                               "\r\n",
                               sender, recver.c_str());
    
    // send request to server
    std::string sreq(req);
    BIO_mywrite(server, sreq);
    
    // read first line
    std::string line;
    if (BIO_mygets(server, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");
    if (line.find("200 OK") == std::string::npos)
        throw std::runtime_error("Not 200 OK");

    // get recver cert and save it
    std::string fname = recver + "-cert";
    BIO_myread_to_file_until_close(server, fname);

    BIO_free_all(server);
}

/* one POST request to send encrypted msg to server */
void POST_msg(SSL_CTX *ctx)
{
    BIO *server = myssl_connect(hostname, CERT_PORT, ctx);

    BIO_free_all(server);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " hostname msg-filename sender-username" << std::endl;
        exit(1);
    }

    // global vars
    hostname = argv[1];
    fname = argv[2];
    sender = argv[3];
    
    ssl_load();
    SSL_CTX *ctx = create_ssl_ctx();

    std::cout << "Enter receivers, one per line, then Ctrl-D:" << std::endl;
    std::string recver;
    while (std::getline(std::cin, recver)) {
        GET_recver_cert(ctx, recver);
        POST_msg(ctx);
    }

    SSL_CTX_free(ctx); 
    return 0;
}
