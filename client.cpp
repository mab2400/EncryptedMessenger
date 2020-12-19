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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	BIO *sbio;
	int err; char *s;

	int ilen;
	char ibuf[512];
	char *obuf = (char *) "GET / HTTP/1.0\r\n";

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

	sbio=BIO_new(BIO_s_socket());
    // Creating a BIO socket to translate between the regular socket and the SSL methods
	BIO_set_fd(sbio, sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);

	err = SSL_connect(ssl);
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

	SSL_read(ssl, ibuf, 12); 
	ibuf[11] = 0;
	printf("%s\n", ibuf);
	fflush(stdout);

	// write/send request
	// to read the response from the server, use BIO gets to read lines
	//SSL_write(ssl, obuf, sizeof(obuf));
	//printf("SENT GET REQUEST\n");

	BIO_flush(sbio);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}
