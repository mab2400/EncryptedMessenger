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
std::string file_to_string(std::string fname)
{
    std::ifstream file(fname);
    std::stringstream ss;
    ss << file.rdbuf();
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
