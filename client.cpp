#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <algorithm>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define  PASS_PORT  25565   // client auth using username/password
//#define  CERT_PORT  443     // client auth using certificate
#define  CERT_PORT  10834   // client auth using certificate

#define  BUFSIZE    4096

#define  CA_CERT      "../rootca/intermediate/certs/intermediate.cert.pem"
#define  CLIENT_CERT  "../rootca/intermediate/certs/client.cert.pem"
#define  CLIENT_KEY   "../rootca/intermediate/private/client.key.pem"

static int should_exit = 0;

struct server_ctx {
    SSL *ssl;
    BIO *ssl_bio;
    BIO *buf_io;
};

void die(const char *msg)
{
    if (errno)
        perror(msg);
    else
        fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void intHandler(int unused) 
{
    should_exit = 1;
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
    
    // CLIENT
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    // Use the CA CERT
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != 1)
        die("SSL_CTX_use_certificate_file() failed");

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != 1)
        die("SSL_CTX_use_PrivateKey_file() failed");

    if (SSL_CTX_check_private_key(ctx) != 1)
        die("SSL_CTX_check_private_key() failed");

    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1)
        die("SSL_CTX_load_verify_locations() failed");

    return ctx;
}

// Added servaddr parameter so we can fill the server info before calling connect
int create_client_socket(int port, struct sockaddr_in servaddr)
{
    printf("Inside create client socket\n");
    int sock;
    char *serverName = "localhost"; /* TODO: Change later */
    struct hostent *he;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        die("socket() failed");

    printf("Successfully called socket\n");

    if ((he = gethostbyname(serverName)) == NULL)
	die("gethostbyname failed");
    char *serverIP = inet_ntoa(*(struct in_addr *)he->h_addr); /* added serverIP */
    
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(serverIP); /* changed from INADDR_ANY */
    servaddr.sin_port        = htons(port);

    printf("Successfully filled server info\n");
    
    return sock;
}

/* NOT SURE IF I SHOULD HAVE THIS? */
void ssl_server_cleanup(struct server_ctx *sctx)
{
    BIO_flush(sctx->buf_io);
    BIO_free_all(sctx->buf_io);

    /* Wouldn't really make sense to close the server connection. */
    // SSL_shutdown(sctx->ssl);
    // close(SSL_get_fd(sctx->ssl));
    SSL_free(sctx->ssl);
}

int ssl_client_connect(struct server_ctx *sctx,
                      SSL_CTX *ssl_ctx,
                      int clntsock, 
                      int should_verify_server_cert,
		      struct sockaddr_in servaddr)
{
    fprintf(stderr, "Inside ssl_client_connect\n");
    int sock;
    socklen_t servlen = sizeof(servaddr);

    if ((sock = connect(clntsock, (struct sockaddr *)&servaddr, servlen)) < 0) {
        perror("connect() failed");
        return -1;
    }
    fprintf(stderr, "CONNECTED\n");

    sctx->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(sctx->ssl, sock);
    fprintf(stderr, "set file descriptor\n");

    if (should_verify_server_cert)
        SSL_set_verify(sctx->ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
        SSL_set_verify(sctx->ssl, SSL_VERIFY_NONE, NULL);
    fprintf(stderr, "should_verify_server_cert = %d\n", should_verify_server_cert);

    if (SSL_connect(sctx->ssl) <= 0) {
        fprintf(stderr, "SSL_connect() failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(sctx->ssl);
        close(sock);
        return -1;
    }
    fprintf(stderr, "SSL_connect() succeeded.\n");

    sctx->buf_io = BIO_new(BIO_f_buffer());             /* create a buffer BIO */
    sctx->ssl_bio = BIO_new(BIO_f_ssl());               /* create an ssl BIO */
    BIO_set_ssl(sctx->ssl_bio, sctx->ssl, BIO_NOCLOSE); /* assign the ssl BIO to SSL */
    BIO_push(sctx->buf_io, sctx->ssl_bio);              /* add ssl_bio to buf_io */

    return 0;
}

int main()
{
    // Source: http://h30266.www3.hpe.com/odl/axpos/opsys/vmsos84/BA554_90007/ch04s03.html

    SSL_CTX *ctx;
    int clntsock_pass, clntsock_cert;

    signal(SIGINT, intHandler);

    ssl_load();
    ctx = create_ssl_ctx(); 
    // Added
    struct sockaddr_in servaddr;

    // Added extra parameter because we need to fill the servaddr info before calling connect() 
    clntsock_pass = create_client_socket(PASS_PORT, servaddr);
    clntsock_cert = create_client_socket(CERT_PORT, servaddr);

    fd_set fds;
    struct server_ctx server_ctx[1];
    char rbuf[BUFSIZE];

    if (FD_ISSET(clntsock_pass, &fds)
        && ssl_client_connect(server_ctx, ctx, clntsock_pass, 0, servaddr) == 0)
    {
        // TODO: Should I make it ssl_server_cleanup? What do we need to clean up?
        // Should NOT verify server cert
	printf("Inside if statement 1\n");
        BIO_gets(server_ctx->buf_io, rbuf, BUFSIZE);
        ssl_server_cleanup(server_ctx);
    } 
    
    if (FD_ISSET(clntsock_cert, &fds)
        && ssl_client_connect(server_ctx, ctx, clntsock_cert, 1, servaddr) == 0)
    {
        // client auth using certificate
        // TODO: Should I send over the client certificate right here?
        // Should verify server cert
	printf("Inside if statement 2\n");
        BIO_gets(server_ctx->buf_io, rbuf, BUFSIZE);
        ssl_server_cleanup(server_ctx);
    }
    
    SSL_CTX_free(ctx);
}
