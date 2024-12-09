#pragma once
#include <iostream>
#include <vector>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "common.h"

std::vector<SHARE_INT> generateShares_int(int secret, int n, int t, int mod);
std::vector<SHARE_LONG> generateShares_long(unsigned long long privateKey, int n, int t, unsigned long long order);
std::vector<SHARE_BIGNUM> generateShares_BIGNUM(const BIGNUM* privateKey, int n, int t);