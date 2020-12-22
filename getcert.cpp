/* =========== G E T C E R T =========== */

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
#include <sys/wait.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	int err; char *s;

	int ilen;

	struct sockaddr_in sin;
	int sock;
	struct hostent *he;

	SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
	SSL_load_error_strings(); /* load the error strings for good error reporting */

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_default_verify_dir(ctx);
	/* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); */
    // Do we have to write this ourselves?
    /*
     int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
     */

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(25565);

	he = gethostbyname("localhost");
	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
		perror("connect");
		return 2;
	}

	SSL_set_fd(ssl, sock);
	BIO *sbio;
	sbio=BIO_new(BIO_s_socket());
	BIO_set_fd(sbio, sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	BIO *buf_io;
	BIO *ssl_bio;
	char rbuf[1024];
	char wbuf[1024];

	buf_io = BIO_new(BIO_f_buffer()); /* buf_io is type BIO * */
	ssl_bio = BIO_new(BIO_f_ssl()); /* ssl_bio is type BIO * */
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
		return 3;
	}

	/* ===================== Generate the PUBLIC/PRIVATE keys and CSR ===================== */ 

 	pid_t pid = fork();
	if (pid < 0) 
	{
	    fprintf(stderr, "fork failed\n");
	    exit(1);
	} else if (pid == 0) {
	    /* The shell script creates the following files:
	     * 1) certs/ca/client/client-pub.key.pem          --> PUBLIC KEY
	     * 2) certs/ca/client/private/client-priv.key.pem --> PRIVATE KEY
	     * 3) certs/ca/intermediate/csr/client.csr.pem    --> CSR 
	     */
	    execl("./BellovinHW2Solutions/gen-client-key.sh", "BellovinHW2Solutions/gen-client-key.sh", argv[1], argv[2], (char *) 0);
	    fprintf(stderr, "execl failed\n");
	    exit(1);
	}
	
	waitpid(pid, NULL, 0);

	/* ===================== Send the Username, Password, and CSR to the server ===================== */ 

	// First, calculate the size of the CSR file
	FILE* fp = fopen("certs/ca/intermediate/csr/client.csr.pem", "r");
	if (fp == NULL) {
	    printf("File Not Found!\n");
	    return -1;
	}
	fseek(fp, 0L, SEEK_END);
	int res = ftell(fp);
	fclose(fp);

	// Send Username and Plain Password to the server as the first 2 lines of the body
	char request[4096];
	sprintf(request, "GET /getcert HTTP/1.0\r\nContent-Length: %d\r\n\r\nUsername: %s\r\nPassword: %s\r\n", res, argv[1], argv[2]);
	printf(request);
	BIO_puts(buf_io, request);
	BIO_flush(buf_io);

	// Send the content of the CSR in the rest of the body 
	printf("Sending CSR to server\n");
	size_t freadresult;
	char buffer[1000];
	FILE *f = fopen("certs/ca/intermediate/csr/client.csr.pem", "r");
	while((freadresult = fread(buffer, 1, 1000, f)) > 0)
	    SSL_write(ssl, buffer, freadresult);

	    //BIO_puts(buf_io, buffer); // TODO: might need to change back to SSL_write
	fclose(f);
	printf("Successfully sent CSR to server\n");

	/* ===================== Receive the signed certificate from the server =============== */

	// Get the 200 OK line and blank line
	char line2[1000];
	int ret1;
	while((ret1 = BIO_gets(buf_io, line2, 1000)) > 0)
	{
	    BIO_gets(buf_io, line2, 1000); 
	    printf(line2);
	    if(strcmp(line2, "\r\n")==0)
	        break;
	}

	FILE *signed_cert = fopen("client_cert.pem", "w"); // Creating a new file to write into
	int ret;
	char request2[1000];
	printf("Starting to read in the file\n");
	while((ret = BIO_gets(buf_io, request2, 100)) > 0)
	{
	    printf("%s", request2);
	    fwrite(request2, 1, ret, signed_cert);
	}
	printf("Finished reading in the file\n");
	fclose(signed_cert);

	/* ================================== Free memory structures =============================== */ 

        BIO_free_all(buf_io);
	SSL_CTX_free(ctx); 
	return 0;
}
