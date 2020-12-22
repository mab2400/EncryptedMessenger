#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <algorithm>
#include <string>
#include <stdexcept>
#include <regex>

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

int readline(BIO *bio, std::string& line)
{
    char buf[1000];
    int r;
    if ((r = BIO_gets(bio, buf, sizeof(buf))) > 0)
        line = buf;
    return r;
}

void handle_one_msg_client(BIO *clnt)
{
    std::string line;

    // read first line
    if (readline(clnt, line) <= 0)
        std::runtime_error("readline failed");
    int is_sendmsg = (line.find("sendmsg") != std::string::npos);
    int is_recvmsg = (line.find("recvmsg") != std::string::npos);

    // read headers
    while((readline(clnt, line)) > 0)
        if (line != "\r\n")
            break;

    if (is_sendmsg) {

        std::vector<std::string> recvers;

        // read recvers
        while((readline(clnt, line)) > 0) {
            if (line == "\r\n")
                break;
            recvers.push_back(line);
        }

        // TODO: send recver's certs to client

        // TODO: receive client's message and store

    } else if (is_recvmsg) {
        
        // TODO: send client a single encrypted msg, then delete from server

    } else {
        throw std::runtime_error("HTTP bad first line");
    }
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
	    char request[1000];
	    int is_getcert = 0;
	    int is_changepw = 0;

	    // Read the first line of the request to determine which client is connecting
            BIO_gets(client_ctx->buf_io, request, 100);
	    char *token_separators = (char *) " "; 
	    char *method = strtok(request, token_separators);
	    char *client_name = strtok(NULL, token_separators);
	    client_name++; // Move past the "/" 
	    if(strcmp(client_name, "getcert")==0)
		is_getcert = 1;
	    if(strcmp(client_name, "changepw")==0)
		is_changepw = 1;

	    // Read the second line, aka the Content-Length for the CSR.
	    BIO_gets(client_ctx->buf_io, request, 100);
	    char *content_length_word = strtok(request, token_separators);
	    char *c_l = strtok(NULL, token_separators);
	    int csr_length = atoi(c_l); 

	    // Read the third line, which should be a blank line.
	    BIO_gets(client_ctx->buf_io, request, 100);
	    if(strcmp(request, "\r\n")!=0)
		exit(1);

	    // Read the request BODY (Username + Password) from the client
	    char username[100];
	    char password[100];
	    int iteration = 1;
	    while(1)
	    {
		if(iteration > 2) // Only want to read the first 2 lines of the body
		    break;

		BIO_gets(client_ctx->buf_io, request, 100);

		/* Extracting the username and password from the request: */
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
		iteration++;
	    }

	    printf("Content-Length: %d\n", csr_length);
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

		/* Read the GETCERT CSR from the rest of the request body.
		 * Write it into a file. */ 
	        FILE *csr_file = fopen("getcert_csr.pem", "w");
		char request2[1000];
	        int ret;
		int sum = 0;
	        while((ret = BIO_gets(client_ctx->buf_io, request2, 100)) > 0)
	        {
		    sum += ret;
		    printf("%s", request2);
		    fwrite(request2, 1, ret, csr_file);
		    if(sum == csr_length)
			break;
	        }
	        fclose(csr_file);

		// Generate the client certificate: TLS/encryption/signing cert
		pid_t pid = fork();
		if (pid < 0)
		{
		    fprintf(stderr, "fork failed\n");
		    exit(1);
		} else if (pid == 0) {
		    /* Create the signed certificate.
		     * Located at getcert.cert.pem */
		    execl("./BellovinHW2Solutions/gen-client-cert.sh", "BellovinHW2Solutions/gen-client-cert.sh", (char *) 0);
		    fprintf(stderr, "execl failed\n");
		    exit(1);
		}

		waitpid(pid, NULL, 0);

		// Send the client certificate to the client
		// First, send the 200 OK line
		char line[1000];
		sprintf(line, "HTTP/1.1 200 OK\r\n\r\n");
		BIO_puts(client_ctx->buf_io, line);
		BIO_flush(client_ctx->buf_io);

		size_t freadresult;
		char buffer[1000];
		FILE *f = fopen("getcert.cert.pem", "r");
		if(f == NULL)
		    printf("FILE NOT FOUND\n");
		while((freadresult = fread(buffer, 1, 1000, f)) > 0)
		    SSL_write(client_ctx->ssl, buffer, freadresult);
		fclose(f);

		/* TODO: Store the certificate somewhere on the server side as well. */

	    } else if(is_changepw) {

		// Read the new password (third line of the request body) from the client
		char new_pwd[100];
		BIO_gets(client_ctx->buf_io, request, 100);
		char *new_pass_setup = strtok(request, token_separators);
	        char *new_password = strtok(NULL, token_separators);
		if(strcmp(new_pass_setup, "New Password:")==0)
		{
		    strncpy(new_pwd, new_password, strlen(new_password)-2); // -2 to get rid of \r\n at the end 
		    password[strlen(new_password)-2] = 0; // null-terminate it
		}

		/* TODO: Save the new password in a file. */

		/* Read the CHANGEPW CSR from the rest of the request body.
		 * Write it into a file. */ 
	        FILE *csr_file = fopen("changepw_csr.pem", "w");
		char request2[1000];
	        int ret;
		int sum = 0;
	        while((ret = BIO_gets(client_ctx->buf_io, request2, 100)) > 0)
	        {
		    sum += ret;
		    printf("%s", request2);
		    fwrite(request2, 1, ret, csr_file);
		    if(sum == csr_length)
			break;
	        }
	        fclose(csr_file);

		// Generate the client certificate: TLS/encryption/signing cert
		pid_t pid = fork();
		if (pid < 0)
		{
		    fprintf(stderr, "fork failed\n");
		    exit(1);
		} else if (pid == 0) {
		    /* Create the signed certificate.
		     * Located at getcert.cert.pem */
		    execl("./BellovinHW2Solutions/gen-client-cert.sh", "BellovinHW2Solutions/gen-client-cert.sh", (char *) 0);
		    fprintf(stderr, "execl failed\n");
		    exit(1);
		}

		waitpid(pid, NULL, 0);

		// Send the client certificate to the client
		// First, send the 200 OK line
		char line[1000];
		sprintf(line, "HTTP/1.1 200 OK\r\n\r\n");
		BIO_puts(client_ctx->buf_io, line);
		BIO_flush(client_ctx->buf_io);

		size_t freadresult;
		char buffer[1000];
		FILE *f = fopen("getcert.cert.pem", "r");
		if(f == NULL)
		    printf("FILE NOT FOUND\n");
		while((freadresult = fread(buffer, 1, 1000, f)) > 0)
		    SSL_write(client_ctx->ssl, buffer, freadresult);
		fclose(f);

		/* TODO: Store the certificate somewhere on the server side as well. */
	    }

            ssl_client_cleanup(client_ctx);
        } 
        
        if (FD_ISSET(servsock_cert, &fds)
            && ssl_client_accept(client_ctx, ctx, servsock_cert, 1) == 0)
        {
            // TODO: verify
	        // see cms_ver.c for verifying the client certificate

            handle_one_msg_client(client_ctx->buf_io);
            ssl_client_cleanup(client_ctx);
        }
    }

    SSL_CTX_free(ctx);
}
