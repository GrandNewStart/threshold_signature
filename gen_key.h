#pragma once
#include <iostream>
#include <openssl/bn.h>

int generateKey_int(int min, int max);
unsigned long long generateKey_long(unsigned long long mod);
BIGNUM* generateKey_BIGNUM();