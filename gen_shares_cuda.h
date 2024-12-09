#pragma once

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <random>
#include <cuda_runtime.h>

#include "common.h"

std::vector<SHARE_INT> generateShares_int_CUDA(int secret, int n, int t, int mod);
std::vector<SHARE_LONG> generateShares_long_CUDA(unsigned long long privateKey, int n, int t, unsigned long long order);
std::vector<SHARE_BIGNUM> generateShares_BIGNUM_CUDA(const BIGNUM* privateKey, int n, int t, const BIGNUM* mod);