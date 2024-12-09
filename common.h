#pragma once

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

struct SHARE_INT {
    int x;
    int y;
};

struct SHARE_BIGNUM {
    BIGNUM* x;
    BIGNUM* y;
};

struct SHARE_LONG {
    unsigned long long x;
    unsigned long long y;
};

std::string bytesToHex(const std::vector<unsigned char>& bytes);
std::string bignumToHex(const BIGNUM* bn);
std::string bufferToHex(const unsigned char* buffer, size_t len);
std::string sha256(const std::string& message);