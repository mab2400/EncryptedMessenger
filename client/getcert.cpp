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
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int remove_file(char *filename)
{
 	pid_t pid = fork();
	if (pid < 0) 
	{
	    fprintf(stderr, "fork failed\n");
	    exit(1);
	} else if (pid == 0) {
	    // The shell script removes the given file 
	    execl("./remove-file.sh", "remove-file.sh", filename, (char *) 0);
	    fprintf(stderr, "execl failed\n");
	    exit(1);
	}
	
	waitpid(pid, NULL, 0);

	return 0;
}

int main(int argc, char **argv)
{

	if (argc != 4)
	{
	    std::cerr << "usage: " << argv[0] << " <hostname> <username> <password>" << std::endl;
	    exit(1);
	}

	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth;
	int err; char *s;

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

	he = gethostbyname(argv[1]);
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
	    // The shell script creates the CSR file <username>.csr.pem
	    execl("./gen-client-keys-and-csr.sh", "gen-client-keys-and-csr.sh", argv[2], argv[3], (char *) 0);
	    fprintf(stderr, "execl failed\n");
	    exit(1);
	}
	
	waitpid(pid, NULL, 0);

	/* ===================== Send the Username, Password, and CSR to the server ===================== */ 
	// First, calculate the size of the CSR file
	char csr_name[1000];
	snprintf(csr_name, strlen(".csr.pem") + strlen(argv[2]) + 1, "%s.csr.pem", argv[2]); 
	FILE* fp = fopen(csr_name, "r");
	if (fp == NULL) {
	    printf("File Not Found!\n");
	    return -1;
	}
	fseek(fp, 0L, SEEK_END);
	int res = ftell(fp);
	fclose(fp);

	// Send username, password, new password, and content-length as the 4 headers.
	char request[4096];
	sprintf(request, "GET /getcert HTTP/1.0\r\nUsername: %s\r\nPassword: %s\r\nNew Password: %s\r\nContent-Length: %d\r\n\r\n", argv[2], argv[3], "", res);
	printf("-----------------------------------\n");
	printf("Sent:\n");
	printf("%s", request);
	BIO_puts(buf_io, request);
	BIO_flush(buf_io);

	// Send the content of the CSR in the rest of the body 
	size_t freadresult;
	char buffer[1000];
	FILE *f = fopen(csr_name, "r");
	while((freadresult = fread(buffer, 1, 1000, f)) > 0)
	    SSL_write(ssl, buffer, freadresult);
	fclose(f);
	remove_file(csr_name);

	/* ===================== Receive the signed certificate from the server =============== */

	// Get the 200 OK line and blank line
	char line2[1000];
	int ret1;
	printf("Server said:\n");
	while((ret1 = BIO_gets(buf_io, line2, 1000)) > 0)
	{
	    printf("%s", line2);
	    BIO_gets(buf_io, line2, 1000); 
	    if(strncmp(line2, "\r\n", strlen("\r\n") + 1)==0)
	        break;
	}

	char cert_file[1000];
	snprintf(cert_file, strlen("-cert.pem") + strlen(argv[2]) + 1, "%s-cert.pem", argv[2]); 
	FILE *signed_cert = fopen(cert_file, "w"); // Creating a new file to write into
	int ret;
	char request2[1000];
	while((ret = BIO_gets(buf_io, request2, 100)) > 0)
	    fwrite(request2, 1, ret, signed_cert);
	fclose(signed_cert);

	/* ================================== Free memory structures =============================== */ 

        BIO_free_all(buf_io);
	SSL_CTX_free(ctx); 
	return 0;
}
