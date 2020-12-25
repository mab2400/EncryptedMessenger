#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <crypt.h>

#include <algorithm>
#include <string>
#include <stdexcept>
#include <regex>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cstdio>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "../common.hpp"

#define  BUFSIZE    4096

#define  INTER_CERT       "certs/ca/intermediate/certs/ca-chain.cert.pem"
#define  SERVER_CERT      "certs/ca/server/certs/server.cert.pem"
#define  SERVER_KEY       "certs/ca/server/private/server.key.pem"
#define  SERVER_KEY_PASS  "topsecretserverpassword"
#define  INTER_KEY_PASS   "lesstopsecretpassword" 

#define  USERDIR      "users/"

static int should_exit = 0;

struct client_ctx {
    SSL *ssl;
    BIO *ssl_bio;
    BIO *buf_io;
};

void intHandler(int unused) 
{
    should_exit = 1;
}

int pkey_passwd_cb(char *buf, int size, int rwflag, void *pkey_pass)
{
    strncpy(buf, SERVER_KEY_PASS, size);
    buf[size - 1] = '\0';
    return(strlen(buf));
}

SSL_CTX *create_ssl_ctx()
{
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != 1)
        die("SSL_CTX_use_certificate_file() failed");

    SSL_CTX_set_default_passwd_cb(ctx, &pkey_passwd_cb); // call this

    char passwdbuf[256]; 
    SSL_CTX_set_default_passwd_cb_userdata(ctx, passwdbuf); // call this before use_private_key

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != 1)
        die("SSL_CTX_use_PrivateKey_file() failed");

    if (SSL_CTX_check_private_key(ctx) != 1)
        die("SSL_CTX_check_private_key() failed");

    if (SSL_CTX_load_verify_locations(ctx, INTER_CERT, NULL) != 1)
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

void handle_error(struct client_ctx *client_ctx, char *error_msg)
{
    fprintf(stderr, "Error: %s\n", error_msg);
    char error_to_send[1000];
    sprintf(error_to_send, "HTTP/1.0 400 Bad Request\r\n\r\nError: %s\r\n", error_msg);
    BIO_puts(client_ctx->buf_io, error_to_send);
    BIO_flush(client_ctx->buf_io);
    ssl_client_cleanup(client_ctx);
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

    cctx->ssl = create_SSL(ssl_ctx);
    SSL_set_fd(cctx->ssl, clntsock);

    if (should_verify_client_cert)
        SSL_set_verify(cctx->ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
        SSL_set_verify(cctx->ssl, SSL_VERIFY_NONE, NULL);

    int r;
    if ((r = SSL_accept(cctx->ssl)) <= 0) {
        fprintf(stderr, "SSL_accept() failed: error code %d\n", SSL_get_error(cctx->ssl, r));
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
	    fprintf(stderr, "execl failed in remove_file function\n");
	    exit(1);
	}
	
	waitpid(pid, NULL, 0);

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
    std::cerr << "handle_sendmsg_1" << std::endl
              << "Sender=" << sender << ", Recver=" << recver << std::endl;

    if (!is_valid_username(sender))
        throw std::runtime_error("bad sender username");
    if (!is_valid_username(recver))
        throw std::runtime_error("bad recver username");

    std::string cert_fname = USERDIR + recver + "/cert";
    std::string cert = read_file_into_string(cert_fname);

    BIO_mywrite(clnt, "HTTP/1.0 200 OK\r\n\r\n");
    BIO_mywrite(clnt, cert);
}

/* client sends us encrypted message, we put it in recver's pending */
void handle_sendmsg_2(BIO *clnt,
                      std::string sender,
                      std::string recver,
                      int content_length)
{
    std::cerr << "handle_sendmsg_1" << std::endl
              << "Sender=" << sender << ", Recver=" << recver
              << ", Content-Length=" << content_length << std::endl;

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
    write_string_to_file(fname, sender + "\n" + std::string(buf.get(), content_length));
    BIO_mywrite(clnt, "HTTP/1.0 200 OK\r\n\r\n");
}

/* send one encrypted message to client */
void handle_recvmsg_1(BIO *clnt, std::string recver)
{
    if (!is_valid_username(recver))
        throw std::runtime_error("bad recver username");

    std::string msg_fname = get_msg_fname(recver, BIGGEST_USED);
    std::string data = read_file_into_string(msg_fname);

    int sender_pos_end = data.find("\n");
    std::string sender = data.substr(0, sender_pos_end);
    std::string msg = data.substr(sender_pos_end + 1);

    BIO_mywrite(clnt, "HTTP/1.0 200 OK\r\n"
                      "Sender: " + sender + "\r\n"
                      "\r\n");
    BIO_mywrite(clnt, msg);

    std::remove(msg_fname.c_str());
}

/* client tells us who the sender was, we send the sender's cert */
void handle_recvmsg_2(BIO *clnt, std::string sender)
{
    std::cerr << "handle_recvmsg_2" << std::endl
              << "Sender=" << sender << std::endl;

    if (!is_valid_username(sender))
        throw std::runtime_error("bad sender username");

    std::string cert_fname = USERDIR + sender + "/cert";
    std::string cert = read_file_into_string(cert_fname);

    BIO_mywrite(clnt, "HTTP/1.0 200 OK\r\n\r\n");
    BIO_mywrite(clnt, cert);
}


/* handle one connection from sendmsg or recvmsg */
void handle_one_msg_client(BIO *clnt)
{
    std::string line;
    auto sender_rgx = std::regex("Sender: [\\w.+-]+", std::regex_constants::icase);
    auto recver_rgx = std::regex("Recver: [\\w.+-]+", std::regex_constants::icase);
    auto content_length_rgx = std::regex("Content-Length: [0-9]+", std::regex_constants::icase);

    std::cerr << "-----------------------------------" << std::endl;

    // read first line
    if (BIO_mygets(clnt, line) <= 0)
        throw std::runtime_error("BIO_mygets failed (failed to read first line)");
    
    std::cerr << line << std::endl;

    int is_sendmsg_1 = (line.find("GET /sendmsg/1 HTTP") != std::string::npos);
    int is_sendmsg_2 = (line.find("POST /sendmsg/2 HTTP") != std::string::npos);
    int is_recvmsg_1 = (line.find("GET /recvmsg/1 HTTP") != std::string::npos);
    int is_recvmsg_2 = (line.find("GET /recvmsg/2 HTTP") != std::string::npos);

    if (!(is_sendmsg_1 || is_sendmsg_2 || is_recvmsg_1 || is_recvmsg_2)) {
        throw std::runtime_error("HTTP bad first line");
    }

    std::string sender, recver;
    int content_length = 0;

    // read headers
    while((BIO_mygets(clnt, line)) > 0) {
        if (line == "\r\n")
            break;
        line = remove_newline(line);

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
    else if (is_recvmsg_1)
        handle_recvmsg_1(clnt, recver);
    else if (is_recvmsg_2)
        handle_recvmsg_2(clnt, sender);
}

/* returns a boolean -- true if matches, false otherwise */ 
/*
int check_pass_valid(char *username, char *try_cstr) {
    
    // retrieve password entry
    char passfilename[256];
    snprintf(passfilename, sizeof(passfilename), "users/%s/password.txt", username);

    FILE *passfile = fopen(passfilename, "r");
    char entry[4096];
    fgets(entry, sizeof(entry), passfile);
    fclose(passfile);
    std::cout << "entry: " << entry << std::endl;
    
    std::string old_hash(entry);

    // check hash
    size_t old_salt_len = old_hash.find_last_of('$');
    std::cout << "salt len: " <<  old_salt_len << std::endl;

    std::string old_salt = old_hash.substr(0, old_salt_len);
    std::cout << "old salt: " << old_salt << std::endl;

    std::string try_pass(try_cstr);
    std::string try_hash(crypt(try_pass.c_str(), old_salt.c_str()));
    std::cout << "encrypted: " << try_hash << std::endl;

    int match = old_hash == try_hash;
    std::cout << "match is " << match << std::endl;

    return match == 0;
}
*/

/* changes the user's password by putting a new hash in their file */
/*
int replace_pass(char *username, char *new_pass) {
    std::cout << "string to encrypt: " << new_pass << std::endl;

    char saltbuf[256];
    char *new_salt = crypt_gensalt_rn(NULL, 0, NULL, 0, saltbuf, sizeof(saltbuf));
    std::cout << "generated salt: " << new_salt << std::endl;
    
    char *new_hash = crypt(new_pass, new_salt);
    std::cout << "encrypted: " << new_hash << std::endl;
   
    char passfilename[256];
    snprintf(passfilename, sizeof(passfilename), "users/%s/password.txt", username);

    FILE *passfile = fopen(passfilename, "w");
    fputs(new_hash, passfile);
    fclose(passfile);

    return 0;

}
*/


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
	    int is_changepw = 0;

	    // Read the first line of the request to determine which client is connecting
            if(BIO_gets(client_ctx->buf_io, request, 100) <= 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    printf("-----------------------------------\n");
	    printf("%s", request);
	    char *token_separators = (char *) " "; 
	    char *method = strtok(request, token_separators);
	    char *client_name = strtok(NULL, token_separators);

            if (!method || !client_name) {
	        char error[1000];
	        snprintf(error, strlen("Method or client_name is null") + 1, "Method or client_name is null");
	        handle_error(client_ctx, error);
	        continue;
            }

	    client_name++; // Move past the "/" 
	    if(strncmp(client_name, "changepw", strlen("changepw") + 1)==0)
		is_changepw = 1;

	    /* Extracting the username and password from the next two header lines: */
	    // Read the next header line, aka the New Password for changepw (blank if getcert).
	    if(BIO_gets(client_ctx->buf_io, request, 100) <= 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    printf("%s", request);
	    char username[100];
	    char *user_setup = strtok(request, token_separators);
	    char *plain_user = strtok(NULL, token_separators);
	    if(!user_setup || !plain_user)
	    {
	        char error[1000];
	        snprintf(error, strlen("User header or username is null") + 1, "User header or username is null");
	        handle_error(client_ctx, error);
	        continue;
	    }

	    if(strncmp(user_setup, "Username:", strlen("Username:") + 1)==0)
	    {
		strncpy(username, plain_user, strlen(plain_user)-2); // -2 to get rid of \r\n at the end 
		username[strlen(plain_user)-2] = 0; // null-terminate it
		if(!is_valid_username(username)) 
		{
		    char error[1000];
		    snprintf(error, strlen("Invalid username") + 1, "Invalid username");
		    handle_error(client_ctx, error);
		    continue;
		}
	    } else {
		char error[1000];
		snprintf(error, strlen("Ill-formatted header") + 1, "Ill-formatted header");
		handle_error(client_ctx, error);
		continue;
	    }

	    if(BIO_gets(client_ctx->buf_io, request, 100) <= 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    printf("%s", request);
	    char password[100];
	    char *pass_setup = strtok(request, token_separators);
	    char *plain_pass = strtok(NULL, token_separators);
	    if(!pass_setup || !plain_pass)
	    {
	        char error[1000];
	        snprintf(error, strlen("Password header or password is null") + 1, "Password header or password is null");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    if(strncmp(pass_setup, "Password:", strlen("Password:") + 1)==0)
	    {
		if(strlen(plain_pass)<=4)
		{
		    char error[1000];
		    snprintf(error, strlen("Password too short") + 1, "Password too short");
		    handle_error(client_ctx, error);
		    continue;
		}
		strncpy(password, plain_pass, strlen(plain_pass)-2); // -2 to get rid of \r\n at the end 
		password[strlen(plain_pass)-2] = 0; // null-terminate it
	    } else {
		char error[1000];
		snprintf(error, strlen("Ill-formatted header") + 1, "Ill-formatted header");
		handle_error(client_ctx, error);
		continue;
	    }

	    // Read the next header line, aka the New Password for changepw (blank if getcert).
	    char new_pwd[100];
	    if(BIO_gets(client_ctx->buf_io, request, 100) <= 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    printf("%s", request);
	    char *new_setup = strtok(request, token_separators);
	    char *new_pass_setup = strtok(NULL, token_separators);
	    char *new_password = strtok(NULL, token_separators);
	    if(!new_setup || !new_pass_setup || (!new_password && is_changepw))
	    {
	        char error[1000];
	        snprintf(error, strlen("Password header is ill-formatted") + 1, "Password header is ill-formatted");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    if((strncmp(new_setup, "New", strlen("New") + 1)==0) && (strncmp(new_pass_setup, "Password:", strlen("Password:") + 1)==0)) 
	    {
		if(strlen(new_password)>0)
		{
		    strncpy(new_pwd, new_password, strlen(new_password)-2); // -2 to get rid of \r\n at the end 
		    new_pwd[strlen(new_password)-2] = 0; // null-terminate it
		} else if(is_changepw) {
		    char error[1000];
		    snprintf(error, strlen("No password provided for changepw") + 1, "No password provided for changepw");
		    handle_error(client_ctx, error);
		    continue;
		}

	    } else {
		char error[1000];
		snprintf(error, strlen("Ill-formatted header") + 1, "Ill-formatted header");
		handle_error(client_ctx, error);
		continue;
	    }

	    // Read the next header line, aka the Content-Length for the CSR.
	    if(BIO_gets(client_ctx->buf_io, request, 100) <= 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    printf("%s", request);
	    char *content_length_word = strtok(request, token_separators);
	    char *c_l = strtok(NULL, token_separators);

            if (!content_length_word || !c_l) {
		char error[1000];
		snprintf(error, strlen("Content-length word or value is null") + 1, "Content-Length word or value is null");
		handle_error(client_ctx, error);
		continue;
            }

            int csr_length = atoi(c_l);

	    // Read the last line, which should be a blank line.
	    if(BIO_gets(client_ctx->buf_io, request, 100) <= 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }
	    printf("%s", request);
	    if(strncmp(request, "\r\n", strlen("\r\n") + 1)!=0)
	    {
		char error[1000];
		snprintf(error, strlen("Ill-formatted request") + 1, "Ill-formatted request");
		handle_error(client_ctx, error);
		continue;
	    }

	    // Now that we have the Username and Password, we need to verify that
	    // the credentials are correct. This happens for BOTH GETCERT and CHANGEPW.
  
            //int passwordOk = check_pass_valid(username, plain_pass);
	    
	    //
	    // TODO FOR MIA: If passwords do not match:
	    /*
		char error[1000];
		snprintf(error, strlen("Incorrect password") + 1, "Incorrect password");
		handle_error(client_ctx, error);
		continue;
	    */

	    // If CHANGEPW, then save the new password into users/<username>/password.txt 
	    // Execute the shell script: save-password.sh (which takes in username + password)

	    if(is_changepw)
	    {
	    /*
                //replace_pass(username, new_pwd);
		
                pid_t pid = fork();
		if (pid < 0)
		{
		    fprintf(stderr, "fork failed\n");
		    exit(1);
		} else if (pid == 0) {
		    execl("./save-password.sh", "save-password.sh", username, new_pwd, (char *) 0);
		    fprintf(stderr, "execl failed\n");
		    exit(1);
		}
		waitpid(pid, NULL, 0);
            */
	    }

	    /* Read the CSR from the rest of the request body.
	     * Write it into a file. */ 
	    char csr_filename[1000];
	    snprintf(csr_filename, strlen("users//csr_temp.pem") + strlen(username) + 1, "users/%s/csr_temp.pem", username);
	    FILE *csr_file = fopen(csr_filename, "w");
	    if(csr_file == NULL)
		printf("CSR FILE NOT FOUND\n");
	    char request2[1000];
	    int ret;
	    int sum = 0;
	    while((ret = BIO_gets(client_ctx->buf_io, request2, 100)) > 0)
	    {
		sum += ret;
		fwrite(request2, 1, ret, csr_file);
		if(sum == csr_length)
		    break;
	    }
	    fclose(csr_file);
	    if(ret < 0)
	    {
	        char error[1000];
	        snprintf(error, strlen("BIO_gets failed") + 1, "BIO_gets failed");
	        handle_error(client_ctx, error);
	        continue;
	    }

	    // Execute the script that creates the certificate from the CSR (takes in the username) 
	    // Saves the client cert in the file /users/<username>/cert
	    pid_t pid = fork();
	    if (pid < 0)
	    {
		fprintf(stderr, "fork failed\n");
		exit(1);
	    } else if (pid == 0) {
		execl("./gen-client-cert.sh", "gen-client-cert.sh", username, INTER_KEY_PASS, (char *) 0);
		fprintf(stderr, "execl failed\n");
		return -1;
	    }
	    waitpid(pid, NULL, 0);
	    remove_file(csr_filename); // Deleting the temporary CSR file.

	    // Send the client certificate to the client
	    // 1) First, send the 200 OK line
	    char line[1000];
	    sprintf(line, "HTTP/1.0 200 OK\r\n\r\n");
	    BIO_puts(client_ctx->buf_io, line);
	    BIO_flush(client_ctx->buf_io);

	    // 2) Then send the certificate 
	    size_t freadresult;
	    char buffer[1000];
	    char cert_filename[1000];
	    snprintf(cert_filename, strlen("users//cert") + strlen(username) + 1, "users/%s/cert", username);
	    FILE *f = fopen(cert_filename, "r"); // Server-side copy of the client certificate.
	    if(f == NULL)
		printf("FILE NOT FOUND\n");
	    while((freadresult = fread(buffer, 1, 1000, f)) > 0)
		SSL_write(client_ctx->ssl, buffer, freadresult);
	    fclose(f);

            ssl_client_cleanup(client_ctx);
        } 
        
        if (FD_ISSET(servsock_cert, &fds)
            && ssl_client_accept(client_ctx, ctx, servsock_cert, 1) == 0)
        {
            // TODO: change flag from 0 to 1 in ssl_client_accept ^^
            //       to require certificate or something

            try {
                handle_one_msg_client(client_ctx->buf_io);
            } catch (std::exception& e) {
                std::cout << e.what() << ": going back to accept()" << std::endl;
                std::string teapot("HTTP/1.0 418 IM A FUCKING TEAPOT\r\n\r\n");  
                BIO_mywrite(client_ctx->buf_io, teapot);
            }
            ssl_client_cleanup(client_ctx);
        }
    }

    SSL_CTX_free(ctx);
}
