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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define  PORT  10834

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

BIO *myssl_connect(char *hostname, SSL_CTX *ssl_ctx)
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
    sin.sin_port = htons(25565);

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

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " hostname" << std::endl;
        exit(1);
    }

    char *hostname = argv[1];
    
    ssl_load();
    SSL_CTX * ctx = create_ssl_ctx();
    BIO *buf_io = myssl_connect(hostname, ctx);

    

    // cleanup
    BIO_free_all(buf_io);
    SSL_CTX_free(ctx); 
    return 0;
}
