#include <cstdio>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

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

#include "../common.hpp"
#include "client-common.hpp"

char *hostname;
char *msg_fname;
char *sender;

/* one GET request to get recver's certificate from server */
void GET_recver_cert(SSL_CTX *ctx, std::string recver)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    std::cerr << "-----------------------------------" << std::endl;

    char req[1000];
    snprintf(req, sizeof(req), "GET /sendmsg/1 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "Recver: %s\r\n"
                               "\r\n",
                               sender, recver.c_str());
    
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

    // get recver cert and save it
    std::string fname = get_user_cert_fname(recver);
    BIO_to_file_until_close(server, fname);
    std::cerr << "Recved and saved recver cert in " << fname << std::endl;

    cleanup(server, ssl);
}

/* one POST request to send encrypted msg to server */
void POST_msg(SSL_CTX *ctx, std::string recver)
{
    SSL *ssl = create_SSL(ctx);
    BIO *server = myssl_connect(hostname, CERT_PORT, ssl);

    /* SIGN USING SENDER CERT/PKEY */

    int flags = CMS_DETACHED | CMS_STREAM;

    // this file shall contain both the sender's cert and pkey
    std::string both_fname = get_user_both_fname(sender);
    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("fork() failed");
    } else if (pid == 0) {
        execl("./catter.sh", "catter.sh",
              get_user_cert_fname(sender).c_str(),
              get_user_pkey_fname(sender).c_str(),
              both_fname.c_str(), (char *)0);
    } else {
        waitpid(pid, NULL, 0);
    }

    BIO *tbio = BIO_new_file(both_fname.c_str(), "r");
    if (!tbio)
        throw std::runtime_error("BIO_new_file() failed");

    X509 *scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    EVP_PKEY *skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!scert || !skey)
        throw std::runtime_error("PEM_read_bio_X509() or PEM_read_bio_PrivateKey() failed");

    // open content being signed
    BIO *original_msg = BIO_new_file(msg_fname, "r");
    if (!original_msg)
        throw std::runtime_error("BIO_new_file() failed");


    // sign content
    CMS_ContentInfo *cms = CMS_sign(scert, skey, NULL, original_msg, flags);

    if (!(flags & CMS_STREAM))
        BIO_reset(original_msg);

    // write out S/MIME message
    BIO *signed_msg = create_mem_bio();
    if (!SMIME_write_CMS(signed_msg, cms, original_msg, flags))
        throw std::runtime_error("SMIME_write_CMS() failed");
    
    CMS_ContentInfo_free(cms);
    EVP_PKEY_free(skey);
    X509_free(scert);
    BIO_free(tbio);
    BIO_free(original_msg);

    std::cerr << "Signing using sender cert/key successful" << std::endl;

    /* ENCRYPT USING RECVER CERT */
    flags = CMS_STREAM;

    tbio = BIO_new_file(get_user_cert_fname(recver).c_str(), "r");
    if (!tbio)
        throw std::runtime_error("BIO_new_file() failed");

    X509 *rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        throw std::runtime_error("PEM_read_bio_X509() failed");

    STACK_OF(X509) *recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        throw std::runtime_error("sk_X509_new_null() or sk_X509_push() failed");

    rcert = NULL;

    cms = CMS_encrypt(recips, signed_msg, EVP_des_ede3_cbc(), flags);
    if (!cms)
        throw std::runtime_error("CMS_encrypt() failed");

    BIO *encrypted_msg = create_mem_bio();
    if (!SMIME_write_CMS(encrypted_msg, cms, signed_msg, flags))
        throw std::runtime_error("SMIME_write_CMS() failed");

    std::cerr << "Ecryption using recver cert successful" << std::endl;
    
    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(tbio);
    BIO_free(signed_msg);

    /* SEND REQ TO SERVER */

    std::cerr << "-----------------------------------" << std::endl;

    char *data;
    int content_length = BIO_get_mem_data(encrypted_msg, &data);

    char req[1000];
    snprintf(req, sizeof(req), "POST /sendmsg/2 HTTP/1.0\r\n"
                               "Sender: %s\r\n"
                               "Recver: %s\r\n"
                               "Content-Length: %d\r\n"
                               "\r\n",
                               sender, recver.c_str(), content_length);

    // send first line + headers to server
    BIO_mywrite(server, req);
    std::cerr << "Sent:" << std::endl << req;

    // send msg to the server
    BIO_mywrite(server, std::string(data, content_length));
    
    // read first line
    std::string line;
    if (BIO_mygets(server, line) <= 0)
        throw std::runtime_error("BIO_mygets failed");
    
    std::cerr << "Server said:" << std::endl << line << std::endl;
    
    if (line.find("200 OK") == std::string::npos)
        throw std::runtime_error("Not 200 OK");

    BIO_skip_headers(server);

    BIO_free(encrypted_msg);
    cleanup(server, ssl);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <hostname> <msg-filename> <sender-username>" << std::endl;
        exit(1);
    }

    // global vars
    hostname = argv[1];
    msg_fname = argv[2];
    sender = argv[3];
    
    ssl_load();
    SSL_CTX *ctx = create_ssl_ctx(get_user_cert_fname(sender).c_str());

    std::cout << "Enter receivers, one per line, then Ctrl-D:" << std::endl;
    std::vector<std::string> recvers;
    std::string line;
    while (std::getline(std::cin, line)) {
        recvers.push_back(line);
    }

    std::cout << std::endl;

    for (std::string& recver : recvers) {
        GET_recver_cert(ctx, recver);
        POST_msg(ctx, recver);
    }

    SSL_CTX_free(ctx); 
    return 0;
}
