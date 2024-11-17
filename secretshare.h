#pragma once
#include <openssl/bn.h>
#include <iostream>
#include <vector>
#include "bignum.h"

namespace secretshare {
	std::vector<std::pair<int, int>> testGenerateShares(int privateKey, int n, int t);
	std::vector<BIGNUM_ptr> generateShares(const BIGNUM* privateKey, int n, int threshold);
}