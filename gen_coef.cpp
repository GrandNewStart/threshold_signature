#include "gen_coef.h"

std::vector<int> generateCoefficients_int(int degree, int mod) {
    std::vector<int> coefficients(degree);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, mod - 1);
    for (int& coeff : coefficients) {
        coeff = dis(gen); // Random coefficient in [1, mod-1]
    }
    return coefficients;
}

std::vector<unsigned long long> generateCoefficients_long(unsigned long long privateKey, int t, unsigned long long order) {
    std::vector<unsigned long long> coefficients;
    coefficients.push_back(privateKey); // Constant term is the secret

    for (int i = 1; i < t; ++i) {
        // Generate random coefficients less than the order
        unsigned long long coeff = rand() % order;
        coefficients.push_back(coeff);
    }

    return coefficients;
}

std::vector<BIGNUM*> generateCoefficients_BIGNUM(const BIGNUM* secret, int t) {
    std::vector<BIGNUM*> coefficients;
    coefficients.push_back(BN_dup(secret)); // Constant term is the secret

    for (int i = 1; i < t; ++i) {
        BIGNUM* coeff = BN_new();
        if (!BN_rand_range(coeff, BN_get0_nist_prime_256())) { // Generate coefficients < order
            throw std::runtime_error("Failed to generate random coefficients");
        }
        coefficients.push_back(coeff);
    }

    return coefficients;
}