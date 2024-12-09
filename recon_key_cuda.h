#pragma once
#include <iostream>
#include <vector>
#include <cuda_runtime.h>

#include "common.h"

int reconstructKey_int_CUDA(const std::vector<SHARE_INT>& shares, int mod);
unsigned long long reconstructKey_long_CUDA(const std::vector<SHARE_LONG>& shares, unsigned long long order);
BIGNUM* reconstructKey_BIGNUM_CUDA(const std::vector<SHARE_BIGNUM>& shares, const BIGNUM* mod);