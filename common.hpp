#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#define  PASS_PORT  25565   // client auth using username/password
#define  CERT_PORT  10834   // client auth using certificate

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
void BIO_mywrite(BIO *bio, std::string data)
{
    if (BIO_write(bio, data.data(), data.length()) != data.length())
        throw std::runtime_error("BIO_mywrite failed");
}

/* read data from bio into std::string */
std::string BIO_myread(BIO *bio, int amount)
{
    std::unique_ptr<char[]> buf(new char[amount]);
    if (BIO_read(bio, buf.get(), amount) != amount)
        throw std::runtime_error("BIO_myread() failed");
}

/* duh */
void BIO_myread_to_file_until_close(BIO *bio, std::string fname)
{
    char buf[4096];
    int r;
    FILE *fp = fopen(fname.c_str(), "wb");
    while ((r = BIO_read(bio, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, r, fp) != r)
            throw std::runtime_error("fwrite failed");
    }
    fclose(fp);
}
