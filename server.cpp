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
#define  CERT_PORT  10834     // client auth using certificate

#define  BUFSIZE    4096

#define  CA_CERT      "certs/ca/intermediate/certs/ca-chain.cert.pem"
#define  SERVER_CERT  "certs/ca/server/certs/server.cert.pem"
#define  SERVER_KEY   "certs/ca/server/private/server.key.pem"

static int should_exit = 0;

struct client_ctx {
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
    
    //fprintf(stderr, "Attempting bind() on PORT %d\n", port);
    if (bind(servsock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind() failed");

    //fprintf(stderr, "bind() succeeded on PORT %d\n", port);
    
    if (listen(servsock, 5) < 0)
        die("listen() failed");

    return servsock;
}

void ssl_client_cleanup(struct client_ctx *cctx)
{
    BIO_flush(cctx->buf_io);
    BIO_free_all(cctx->buf_io);

    SSL_shutdown(cctx->ssl);
    close(SSL_get_fd(cctx->ssl));
    SSL_free(cctx->ssl);
}

int ssl_client_accept(struct client_ctx *cctx,
                      SSL_CTX *ssl_ctx,
                      int servsock, 
                      int should_verify_client_cert)
{
    int clntsock;
    struct sockaddr_in clntaddr;
    socklen_t clntlen = sizeof(clntaddr);

    if ((clntsock = accept(servsock, (struct sockaddr *)&clntaddr, &clntlen)) < 0) {
        perror("accept() failed");
        return -1;
    }

    printf("Connection from %s\n", inet_ntoa(clntaddr.sin_addr));

    cctx->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(cctx->ssl, clntsock);
    //printf("SSL_set_fd succeeded\n");

    if (should_verify_client_cert)
        SSL_set_verify(cctx->ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
        SSL_set_verify(cctx->ssl, SSL_VERIFY_NONE, NULL);
    //printf("should_verify_client_cert succeeded\n");

    if (SSL_accept(cctx->ssl) <= 0) {
        fprintf(stderr, "SSL_accept() failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(cctx->ssl);
        close(clntsock);
        return -1;
    }
    //printf("SSL_accept() succeeded\n");

    BIO *sbio;
    sbio = BIO_new(BIO_s_socket());
    BIO_set_fd(sbio, clntsock, BIO_NOCLOSE);
    SSL_set_bio(cctx->ssl, sbio, sbio);

    cctx->buf_io = BIO_new(BIO_f_buffer());             /* create a buffer BIO */
    cctx->ssl_bio = BIO_new(BIO_f_ssl());               /* create an ssl BIO */
    BIO_set_ssl(cctx->ssl_bio, cctx->ssl, BIO_NOCLOSE); /* assign the ssl BIO to SSL */
    BIO_push(cctx->buf_io, cctx->ssl_bio);              /* add ssl_bio to buf_io */

    return 0;
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
    // Source: http://h30266.www3.hpe.com/odl/axpos/opsys/vmsos84/BA554_90007/ch04s03.html
    
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
	die("signal() failed");

    SSL_CTX *ctx;
    int servsock_pass, servsock_cert;

    signal(SIGINT, intHandler);

    ssl_load();
    ctx = create_ssl_ctx(); 

    servsock_pass = create_server_socket(PASS_PORT);

    servsock_cert = create_server_socket(CERT_PORT);

    while (!should_exit) {
        
        fd_set fds;
        struct client_ctx client_ctx[1];

        my_select(servsock_pass, servsock_cert, &fds);
        if (should_exit) break;

        if (FD_ISSET(servsock_pass, &fds) 
            && ssl_client_accept(client_ctx, ctx, servsock_pass, 0) == 0)
        {
	    // FOR REFERENCE) Send something to the client
            //BIO_puts(client_ctx->buf_io, "Hello world!\r\nTest\r\n\r\n");
	    //BIO_flush(client_ctx->buf_io);

	    char request[1000];
	    int is_getcert = 0;
	    int is_changepw = 0;

	    // Read the first line of the request to determine which client is connecting
            BIO_gets(client_ctx->buf_io, request, 100);
	    printf(request);
	    char *token_separators = (char *) " "; 
	    char *method = strtok(request, token_separators);
	    char *client_name = strtok(NULL, token_separators);
	    client_name++; // Move past the "/" 
	    if(strcmp(client_name, "getcert")==0)
		is_getcert = 1;
	    if(strcmp(client_name, "changepw")==0)
		is_changepw = 1;

	    // Read the rest of the GET request (Username + Password) from the client
	    char username[100];
	    char password[100];
	    while(1)
	    {
		BIO_gets(client_ctx->buf_io, request, 100);

		/* TODO: Extract the Username and Password. This is for BOTH
		 * GETCERT and CHANGEPW. They both require a Username/Password */

		char *token_separators = (char *) " "; 
		char *user_or_pass = strtok(request, token_separators);
	        char *plain= strtok(NULL, token_separators);
		if(strcmp(user_or_pass, "Username:")==0)
		{
		    strncpy(username, plain, strlen(plain)-2); // -2 to get rid of \r\n at the end 
		    username[strlen(plain)-2] = 0; // null-terminate it
		}
		if(strcmp(user_or_pass, "Password:")==0)
		{
		    strncpy(password, plain, strlen(plain)-2); // -2 to get rid of \r\n at the end 
		    password[strlen(plain)-2] = 0; // null-terminate it
		}

		if(strcmp(request, "\r\n")==0)
		    break;
	    }

	    printf("Checking the values of username and password:\n");
	    printf("Username: %s\n", username);
	    printf("Password: %s\n", password);

	    /* TODO: AUTHENTICATION:
	     * Now that we have the Username and Password, we need to verify that
	     * the credentials are correct. Again, I believe this happens for BOTH
	     * GETCERT and CHANGEPW 
	     *
	     * */

	    /* TODO: If credentials were correct, then split off into GETCERT and CHANGEPW. */

	    if(is_getcert)
	    {
		/* TODO: Save the password in a file. */

		/* TODO: Receive the GETCERT CSR from the client. 
		 * What format will this get sent in? OpenSSL function? */
		char csr[1000];
		while(1)
		{
		    BIO_gets(client_ctx->buf_io, csr, 100);
       		    printf(csr);
		    if(strcmp(request, "\r\n")==0)
		        break;
		}

		/* TODO: Send the certificate to the client: TLS/encryption/signing cert */

		/* TODO: Store the certificate somewhere on the server side as well. */

	    } else if(is_changepw)
	    {
		/* TODO:*/ 

	    }

            ssl_client_cleanup(client_ctx);
        } 
        
        if (FD_ISSET(servsock_cert, &fds)
            && ssl_client_accept(client_ctx, ctx, servsock_cert, 1) == 0)
        {
	    /* TODO: This section is for SENDMSG and RECVMSG */

	    char buf[1000];
            // client auth using certificate
	    //printf("Sending Hello world\n");
            BIO_puts(client_ctx->buf_io, "Hello world!\n");
	    BIO_gets(client_ctx->buf_io, buf, 10);
	    buf[9] = 0;
	    printf(buf);
            ssl_client_cleanup(client_ctx);
        }
    
    }

    SSL_CTX_free(ctx);
}
