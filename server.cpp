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
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <cstdio>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define  PASS_PORT  25565   // client auth using username/password
#define  CERT_PORT  10834     // client auth using certificate

#define  BUFSIZE    4096

#define  CA_CERT      "certs/ca/intermediate/certs/ca-chain.cert.pem"
#define  SERVER_CERT  "certs/ca/server/certs/server.cert.pem"
#define  SERVER_KEY   "certs/ca/server/private/server.key.pem"

#define  USERDIR      "users/"

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
    
    if (bind(servsock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind() failed");
    
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

    fprintf(stderr, "Connection from %s\n", inet_ntoa(clntaddr.sin_addr));

    cctx->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(cctx->ssl, clntsock);

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

#define  MAX_PENDING      99999 // max pending msgs for a user
#define  BIGGEST_USED     0
#define  SMALLEST_UNUSED  1
/* e.g. returns stuff like "00001", "00002", etc. */
std::string get_msg_fname(std::string recver, int flag)
{
    std::stringstream ss;
    ss << USERDIR << recver << "/pending";
    
    auto files = std::filesystem::directory_iterator(ss.str());
    int fcount = std::distance(begin(files), end(files));

    if (flag == SMALLEST_UNUSED)
        fcount++;
    
    if (fcount >= MAX_PENDING) 
        throw std::runtime_error("too many pending msgs");

    ss << "/" << std::setfill('0') << std::setw(5) << fcount;
    return ss.str();
}

/* reads one line from bio into std::string (removes trailing newline) */
int BIO_mygets(BIO *bio, std::string& line)
{
    char buf[1000];
    int r;
    if ((r = BIO_gets(bio, buf, sizeof(buf))) > 0)
        line = buf;
    
    // remove all trailing whitespace
    // src: techiedelight.com/trim-string-cpp-remove-leading-trailing-spaces/ 
    line = std::regex_replace(line, std::regex("\\s+$"), std::string(""));

    return r;
}

/* write data from std::string to bio */
int BIO_mywrite(BIO *bio, std::string data)
{
    return BIO_write(bio, data.data(), data.length());
}

/* read entire file contents into std::string */
std::string file_to_string(std::string fname)
{
    std::ifstream file(fname);
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

/* does this username exist in USERDIR? */
bool is_valid_username(const std::string& username) {
    for (const auto& entry : std::filesystem::directory_iterator(USERDIR))
        if (entry.is_directory() && username == entry.path().filename())
            return true;
    return false;
}

/* client tells us who they want the recver to be, we send their cert */
void handle_sendmsg_1(BIO *clnt,
                      std::string sender,
                      std::string recver)
{
    if (!is_valid_username(sender))
        throw std::runtime_error("bad sender username");
    if (!is_valid_username(recver))
        throw std::runtime_error("bad recver username");

    std::string cert_fname = USERDIR + recver + "/cert.pem";
    std::string cert = file_to_string(cert_fname);

    if (BIO_mywrite(clnt, cert) <= 0)
        throw std::runtime_error("could not send recver cert to client");
}

/* client sends us encrypted message, we put it in recver's pending */
void handle_sendmsg_2(BIO *clnt,
                      std::string sender,
                      std::string recver,
                      int content_length)
{
    if (!is_valid_username(sender))
        throw std::runtime_error("bad sender username");
    if (!is_valid_username(recver))
        throw std::runtime_error("bad recver username");
    if (content_length <= 0)
        throw std::runtime_error("bad content-length");

    std::unique_ptr<char[]> buf(new char[content_length]);

    if (BIO_read(clnt, buf.get(), content_length) <= 0)
        throw std::runtime_error("could not read msg contents from client");

    std::string fname = get_msg_fname(recver, SMALLEST_UNUSED);
    std::ofstream file(fname);
    file << std::string(buf.get());
}

/* send one encrypted message to client */
void handle_recvmsg(BIO *clnt, std::string recver)
{
    if (!is_valid_username(recver))
        throw std::runtime_error("bad recver username");

    std::string msg_fname = get_msg_fname(recver, BIGGEST_USED);
    std::string msg = file_to_string(msg_fname);

    if (BIO_mywrite(clnt, msg) <= 0)
        throw std::runtime_error("could not send msg to client");
    
    std::remove(msg_fname.c_str());
}

/* handle one connection from sendmsg or recvmsg */
void handle_one_msg_client(BIO *clnt)
{
    std::string line;
    auto sender_rgx = std::regex("Sender: *", std::regex_constants::icase);
    auto recver_rgx = std::regex("Recver: *", std::regex_constants::icase);
    auto content_length_rgx = std::regex("Content-Length: *", std::regex_constants::icase);

    // read first line
    if (BIO_mygets(clnt, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");

    int is_sendmsg_1 = (line.find("POST /sendmsg/1 HTTP") != std::string::npos);
    int is_sendmsg_2 = (line.find("POST /sendmsg/2 HTTP") != std::string::npos);
    int is_recvmsg = (line.find("GET /recvmsg HTTP") != std::string::npos);

    std::string sender, recver;
    int content_length = 0;

    // read headers
    while((BIO_mygets(clnt, line)) > 0) {
        if (line != "\r\n")
            break;
        int pos = line.find(":") + 2;
        if (std::regex_match(line, sender_rgx)) {
            sender = line.substr(pos);
            std::cerr << "Sender: " << sender << std::endl;
        } else if (std::regex_match(line, recver_rgx)) {
            recver = line.substr(pos);
            std::cerr << "Recver: " << recver << std::endl;
        } else if (std::regex_match(line, content_length_rgx)) {
            content_length = stoi(line.substr(pos));
            std::cerr << "Content-Length: " << content_length << std::endl;
        }
    }

    if (is_sendmsg_1)
        handle_sendmsg_1(clnt, sender, recver);
    else if (is_sendmsg_2)
        handle_sendmsg_2(clnt, sender, recver, content_length);
    else if (is_recvmsg)
        handle_recvmsg(clnt, recver);
    else
        throw std::runtime_error("HTTP bad first line");
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
