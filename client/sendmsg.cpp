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
char *msg_fname;
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

BIO *myssl_connect(char *hostname, int port, SSL *ssl)
{
    struct sockaddr_in sin;
    int sock;
    struct hostent *he;
    int err; char *s;

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
    BIO_set_ssl(ssl_bio, ssl, BIO_NOCLOSE);
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
    SSL *ssl = SSL_new(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "GET /sendmsg/1 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "Recver: %s\r\n"
                               "\r\n",
                               sender, recver.c_str());
    
    // send request to server
    std::string sreq(req);
    BIO_mywrite(server, sreq);
    std::cerr << "Sent:" << std::endl << sreq;

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

    BIO_free_all(server);
    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
}

/* one POST request to send encrypted msg to server */
void POST_msg(SSL_CTX *ctx, std::string recver)
{
    SSL *ssl = SSL_new(ctx);
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
    std::string sreq(req);
    BIO_mywrite(server, sreq);
    std::cerr << "Sent:" << std::endl << sreq;

    // send msg to the server
    BIO_mywrite(server, msg);
    std::cerr << "Sent msg to server" << std::endl;

    BIO_free_all(server);
    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " hostname msg-filename sender-username" << std::endl;
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
