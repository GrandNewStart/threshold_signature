#pragma once

#include "bignum.h"

namespace keygen {
    int generateTestKey();
    bool generateKeyPair(std::string& privateKeyPem, std::string& publicKeyPem);
    BIGNUM_ptr generatePrivateKey();
    BIGNUM_ptr getPublicKey(const BIGNUM* privateKey);

}