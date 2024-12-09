#pragma once
#include <iostream>
#include <vector>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "common.h"

int reconstructKey_int(const std::vector<SHARE_INT>& shares, int mod);
unsigned long long reconstructKey_long(const std::vector<SHARE_LONG>& shares, unsigned long long order);
BIGNUM* reconstructKey_BIGNUM(const std::vector<SHARE_BIGNUM>& shares);