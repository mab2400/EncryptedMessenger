#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//#define  PKEY_PATH  "client-priv.key.pem"

// we shouldn't have put this file in the ../server directory but
// it's too late to change that now
#define  CA_FILE    "../server/certs/ca/intermediate/certs/ca-chain.cert.pem"

std::string get_user_cert_fname(std::string username)
{
    return username + "-cert.pem";
}

SSL_CTX *create_ssl_ctx(const char *cert_path)
{
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1)
        throw std::runtime_error("SSL_use_certificate_file() failed");

    char cert_path_copy[1000];
    strncpy(cert_path_copy, cert_path, strlen(cert_path));
    char *token_separators = (char *) "-"; 
    char *username = strtok(cert_path_copy, token_separators);
    char pkey_path[1000];
    int len_pkey_path = strlen(username) + strlen("-priv.key.pem") + 1;
    snprintf(pkey_path, len_pkey_path, "%s-priv.key.pem", username); 

    if (SSL_CTX_use_PrivateKey_file(ctx, pkey_path, SSL_FILETYPE_PEM) != 1)
        throw std::runtime_error("SSL_use_PrivateKey_file() failed");

    if (SSL_CTX_check_private_key(ctx) != 1)
        throw std::runtime_error("SSL_check_private_key() failed");

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != 1)
        throw std::runtime_error("SSL_CTX_load_verify_locations() failed");

    SSL_CTX_set_default_verify_dir(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

BIO *myssl_connect(const char *hostname, int port, SSL *ssl)
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

void cleanup(BIO *bio, SSL *ssl)
{
    BIO_free_all(bio);
    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
}
