#pragma once

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>

struct BIGNUM_Deleter {
    void operator()(BIGNUM* bn) const {
        if (bn) BN_free(bn);
    }
};
using BIGNUM_ptr = std::unique_ptr<BIGNUM, BIGNUM_Deleter>;

std::string bytesToHex(const std::vector<unsigned char>& bytes);
std::string bignumToHex(const BIGNUM* bn);
std::string bufferToHex(const unsigned char* buffer, size_t len);
std::string sha256(const std::string& message);

std::pair<BIGNUM*, BIGNUM*> generateKeyPair();
BIGNUM* generatePublicKey(const BIGNUM* privateKey);

std::vector<std::pair<BIGNUM*, BIGNUM*>> generateShares(const BIGNUM* privateKey, int n, int t);
std::pair<BIGNUM*, BIGNUM*> reconstructKeyPair(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& shares);