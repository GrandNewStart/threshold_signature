#pragma once

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>

std::vector<std::pair<BIGNUM*, BIGNUM*>> generateSharesCUDA(const BIGNUM* privateKey, int n, int t, const BIGNUM* mod);
std::pair<BIGNUM*, BIGNUM*> reconstructKeyCUDA(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& shares, const BIGNUM* mod);