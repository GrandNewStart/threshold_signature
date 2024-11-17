#pragma once

#include <openssl/bn.h>
#include <iostream>

struct BIGNUM_Deleter {
    void operator()(BIGNUM* bn) const {
        if (bn) BN_free(bn);
    }
};
using BIGNUM_ptr = std::unique_ptr<BIGNUM, BIGNUM_Deleter>;