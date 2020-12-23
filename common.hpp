#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define  PASS_PORT  25565   // client auth using username/password
#define  CERT_PORT  10834   // client auth using certificate

void die(const char *msg)
{
    if (errno)
        perror(msg);
    else
        fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void ssl_load()
{
    // load ssl algos and error strings
    SSL_library_init();
    SSL_load_error_strings();
}

SSL *create_SSL(SSL_CTX *ctx)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        throw std::runtime_error("could not create SSL");
    }
    return ssl;
}

/* read entire file contents into std::string */
std::string read_file_into_string(std::string fname)
{
    std::ifstream file(fname);
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

/* write std::string contents to file */
void write_string_to_file(std::string fname, std::string data)
{
    std::ofstream file(fname);
    file << data;
}

std::string remove_newline(std::string line)
{
    // remove all trailing whitespace
    // src: techiedelight.com/trim-string-cpp-remove-leading-trailing-spaces/ 
    return std::regex_replace(line, std::regex("\\s+$"), std::string(""));
}

/* reads one line from bio into std::string */
int BIO_mygets(BIO *bio, std::string& line)
{
    char buf[1000];
    int r;
    if ((r = BIO_gets(bio, buf, sizeof(buf))) > 0) {
        line = buf;;
    }
    return r;
}

/* write data from std::string to bio */
void BIO_mywrite(BIO *bio, std::string data)
{
    int len = data.length();
    if (BIO_write(bio, data.data(), len) != len)
        throw std::runtime_error("BIO_mywrite failed");
    BIO_flush(bio);
}

/* read data from bio into std::string */
std::string BIO_myread(BIO *bio, int amount)
{
    std::unique_ptr<char[]> buf(new char[amount]);
    if (BIO_read(bio, buf.get(), amount) != amount)
        throw std::runtime_error("BIO_myread() failed");
    return std::string(buf.get());
}

/* duh */
void BIO_read_to_file_until_close(BIO *bio, std::string fname)
{
    char buf[4096];
    unsigned int r;
    FILE *fp = fopen(fname.c_str(), "wb");
    while ((r = BIO_read(bio, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, r, fp) != r)
            throw std::runtime_error("fwrite failed");
    }
    fclose(fp);
}

void BIO_read_to_BIO_until_close(BIO *from, BIO *to)
{
    char buf[4096];
    int r;
    while ((r = BIO_read(from, buf, sizeof(buf))) > 0) {
        if (BIO_write(to, buf, r) != r)
            throw std::runtime_error("BIO_write failed");
    }
}

void BIO_skip_headers(BIO *bio)
{
    std::string line;
    while (BIO_mygets(bio, line))
        if (line == "\r\n")
            break;
}