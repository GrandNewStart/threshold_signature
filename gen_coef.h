#pragma once
#include <iostream>
#include <vector>
#include <random>
#include <openssl/bn.h>
#include <openssl/ec.h>

std::vector<int> generateCoefficients_int(int degree, int mod);
std::vector<unsigned long long> generateCoefficients_long(unsigned long long privateKey, int t, unsigned long long order);
std::vector<BIGNUM*> generateCoefficients_BIGNUM(const BIGNUM* secret, int t);