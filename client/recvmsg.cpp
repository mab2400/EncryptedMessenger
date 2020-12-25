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
#include <sys/wait.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

#include "../common.hpp"
#include "client-common.hpp"

char *hostname;
char *recver;

/* GET request to get sender name and msg from server */
std::string GET_msg(SSL_CTX *ctx, BIO *msgmem)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);
    auto sender_rgx = std::regex("Sender: [\\w.+-]+", std::regex_constants::icase);

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "GET /recvmsg/1 HTTP/1.0\r\n"
                               "Recver: %s\r\n"
                               "\r\n",
                               recver);
    
    // send request to server
    BIO_mywrite(server, req);
    std::cerr << "Sent:" << std::endl << req;

    // read first line
    std::string line;
    if (BIO_mygets(server, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");
    
    std::cerr << "Server said:" << std::endl << line;
    
    if (line.find("200 OK") == std::string::npos)
        throw std::runtime_error("Not 200 OK");

    // read recver header
    if (BIO_mygets(server, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");
    line = remove_newline(line);

    std::cerr << line << std::endl;

    if (!std::regex_match(line, sender_rgx))
        throw std::runtime_error("did not receive sender header");

    std::string sender = line.substr(line.find(":") + 2);

    BIO_skip_headers(server);

    // read encrypted msg into msgmem (memory bio)
    BIO_to_BIO_until_close(server, msgmem);
    std::cerr << "Read encrypted msg into mem bio" << std::endl;

    cleanup(server, ssl);

    return sender;
}

/* one GET request to get sender's certificate from server */
void GET_sender_cert(SSL_CTX *ctx, std::string sender)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "GET /recvmsg/2 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "\r\n",
                               sender.c_str());
    
    // send request to server
    BIO_mywrite(server, req);
    std::cerr << "Sent:" << std::endl << req;

    // read first line
    std::string line;
    if (BIO_mygets(server, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");
    
    std::cerr << "Server said:" << std::endl << line << std::endl;
    
    if (line.find("200 OK") == std::string::npos)
        throw std::runtime_error("Not 200 OK");

    BIO_skip_headers(server);

    // get sender cert and save it
    std::string fname = get_user_cert_fname(sender);
    BIO_to_file_until_close(server, fname);
    std::cerr << "Recved and saved sender cert in " << fname << std::endl;

    cleanup(server, ssl);
}

void process_msg(std::string sender, BIO *msgmem)
{
    char *data;
    size_t content_length = BIO_get_mem_data(msgmem, &data);

    FILE *fp = fopen(".newmsg.txt", "w");
    if (!fp)
        throw std::runtime_error("fopen() failed");
    if (fwrite(data, 1, content_length, fp) != content_length)
        throw std::runtime_error("fwrite() failed");
    fclose(fp);

    /* DECRYPT using recver cert and pkey */

    // this file shall contain both the recvers's cert and pkey
    std::string both_fname = get_user_both_fname(recver);
    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("fork() failed");
    } else if (pid == 0) {
        execl("./catter.sh", "catter.sh",
              get_user_cert_fname(recver).c_str(),
              get_user_pkey_fname(recver).c_str(),
              both_fname.c_str(), (char *)0);
    } else {
        waitpid(pid, NULL, 0);
    }

    BIO *tbio = BIO_new_file(both_fname.c_str(), "r");
    if (!tbio)
        throw std::runtime_error("BIO_new_file() failed");

    X509 *rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    EVP_PKEY *rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        throw std::runtime_error("PEM_read_bio_X509() or PEM_read_bio_PrivateKey() failed");

    BIO *in = BIO_new_file(".newmsg.txt", "r");
    if (!in)
        throw std::runtime_error("BIO_new_file() on newmsg.txt failed");

    CMS_ContentInfo *cms = SMIME_read_CMS(in, NULL);
    if (!cms) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SMIME_read_CMS() on msgmem failed");
    }

    BIO *decrypted_msg = create_mem_bio();
    if (!CMS_decrypt(cms, rkey, rcert, NULL, decrypted_msg, 0))
        throw std::runtime_error("CMS_decrypt() failed");

    std::cerr << "Decryption using recver cert/key successful" << std::endl;
    
    CMS_ContentInfo_free(cms);
    EVP_PKEY_free(rkey);
    X509_free(rcert);
    BIO_free(tbio);
    BIO_free(in);

    /* VERIFY using sender cert */

    std::string cert_fname = get_user_cert_fname(sender);
    X509_STORE *st = X509_STORE_new();
    tbio = BIO_new_file(cert_fname.c_str(), "r");
    if (!tbio)
        throw std::runtime_error("BIO_new_file() failed");

    X509 *sender_cert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!sender_cert)
        throw std::runtime_error("PEM_read_bio_X509() failed");

    BIO *cont;
    cms = SMIME_read_CMS(decrypted_msg, &cont);
    if (!cms)
        throw std::runtime_error("SMIME_read_CMS() failed");

    STACK_OF(X509) *certs = sk_X509_new_null();
    if (!certs)
        throw std::runtime_error("sk_X509_new_null() failed");

    if (!sk_X509_push(certs, sender_cert))
        throw std::runtime_error("sk_X509_push() failed");

    if (!(X509_STORE_load_locations(st, cert_fname.c_str(), NULL)))
        throw std::runtime_error("X509_STORE_load_locations() on cert_fname failed");

    if (!(X509_STORE_load_locations(st, INTER_CERT, NULL)))
        throw std::runtime_error("X509_STORE_load_locations() on INTER_CERT failed");

    if (!(X509_STORE_load_locations(st, ROOT_CERT, NULL)))
        throw std::runtime_error("X509_STORE_load_locations() on ROOT_CERT failed");

    BIO *verified_msg = create_mem_bio();
    if (!CMS_verify(cms, certs, st, cont, verified_msg, CMS_NOINTERN)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("CMS_verify() failed");
    }

    std::cerr << "Verification using sender cert successful" << std::endl;

    CMS_ContentInfo_free(cms);
    sk_X509_pop_free(certs, X509_free);
    X509_STORE_free(st);
    BIO_free(tbio);
    BIO_free(cont);
    BIO_free(decrypted_msg);

    std::cerr << "Now displaying message (and saving in newmsg.txt)" << std::endl;

    content_length = BIO_get_mem_data(verified_msg, &data);
    if (fwrite(data, 1, content_length, stdout) != content_length)
        throw std::runtime_error("fwrite() failed");

    fp = fopen("newmsg.txt", "w");
    if (!fp)
        throw std::runtime_error("fopen() failed");
    if (fwrite(data, 1, content_length, fp) != content_length)
        throw std::runtime_error("fwrite() failed");
    fclose(fp);

    BIO_free(verified_msg);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <hostname> <recver>" << std::endl;
        exit(1);
    }

    // global vars
    hostname = argv[1];
    recver = argv[2];
    
    ssl_load();
    SSL_CTX *ctx = create_ssl_ctx(get_user_cert_fname(recver).c_str());

    BIO *msgmem = create_mem_bio();

    // get the message
    std::string sender = GET_msg(ctx, msgmem);

    // get the sender's certificate
    GET_sender_cert(ctx, sender);

    // decrypt and verify message
    process_msg(sender, msgmem);

    BIO_free(msgmem);
    SSL_CTX_free(ctx); 
    return 0;
}
