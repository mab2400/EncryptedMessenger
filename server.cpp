#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <algorithm>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define  PASS_PORT  25565   // client auth using username/password
#define  CERT_PORT  443     // client auth using certificate

#define  CA_CERT      "../rootca/intermediate/certs/intermediate.cert.pem"
#define  SERVER_CERT  "../rootca/intermediate/certs/server.cert.pem"
#define  SERVER_KEY   "../rootca/intermediate/private/server.key.pem"

void die(const char *msg)
{
    if (errno)
        perror(msg);
    else
        fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

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
    
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != 1)
        die("SSL_CTX_use_certificate_file() failed");

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != 1)
        die("SSL_CTX_use_PrivateKey_file() failed");

    if (SSL_CTX_check_private_key(ctx) != 1)
        die("SSL_CTX_check_private_key() failed");

    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1)
        die("SSL_CTX_load_verify_locations() failed");

    return ctx;
}

int create_server_socket(int port)
{
    struct sockaddr_in addr;
    int servsock;

    if ((servsock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        die("socket() failed");
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    
    if (bind(servsock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind() failed");
    
    if (listen(servsock, 5) < 0)
        die("listen() failed");

    return servsock;
}

void ssl_client_cleanup(SSL *ssl)
{
    int clntsock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(clntsock);
}

SSL *ssl_client_accept(SSL_CTX *ctx, int servsock, int should_verify_client_cert)
{
    SSL *ssl;
    int clntsock;
    struct sockaddr_in clntaddr;
    socklen_t clntlen = sizeof(clntaddr);

    if ((clntsock = accept(servsock, (struct sockaddr *)&clntaddr, &clntlen)) < 0) {
        perror("accept() failed");
        return NULL;
    }

    printf("Connection from %s\n", inet_ntoa(clntaddr.sin_addr));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clntsock);
    if (should_verify_client_cert)
        SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        ssl_client_cleanup(ssl);
        return NULL;
    }

    return ssl;
}

void my_select(int servsock_pass, int servsock_cert, fd_set *read_fds) {
    FD_ZERO(read_fds);
    FD_SET(servsock_pass, read_fds);
    FD_SET(servsock_cert, read_fds);
    select(std::max(servsock_pass, servsock_cert) + 1,
           read_fds, NULL, NULL, NULL);
}

int main()
{
    SSL *ssl;
    SSL_CTX *ctx;
    int servsock_pass, servsock_cert;
    const char *msg = "Hello world!\n";

    ssl_load();
    ctx = create_ssl_ctx();

    servsock_pass = create_server_socket(PASS_PORT);
    servsock_cert = create_server_socket(CERT_PORT);

    while (1) {
        
        fd_set fds;
        my_select(servsock_pass, servsock_cert, &fds);

        if (FD_ISSET(servsock_pass, &fds) 
            && (ssl = ssl_client_accept(ctx, servsock_pass, 0)) != NULL)
        {
            // client auth using username/password
            SSL_write(ssl, msg, strlen(msg));
            ssl_client_cleanup(ssl);
        } 
        
        if (FD_ISSET(servsock_cert, &fds) 
            && (ssl = ssl_client_accept(ctx, servsock_cert, 1)) != NULL)
        {
            // client auth using certificate
            SSL_write(ssl, msg, strlen(msg));
            ssl_client_cleanup(ssl);
        }
    
    }

    SSL_CTX_free(ctx);
}