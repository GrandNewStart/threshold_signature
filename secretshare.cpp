#include <iostream>
#include <vector>
#include <random>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

#include "secretshare.h"

namespace secretshare {

    // y = a0 + a1 x + a2 x^2 + a3 x^3 + a4 x^4 + ... at-1 x^t-1
    int evaluatePolynomial(const std::vector<int>& coefficients, int x) {
        int result = 0;
        int power = 1;

        for (int coeff : coefficients) {
            result += coeff * power;
            power *= x;
        }

        return result;
    }

    std::vector<std::pair<int, int>> testGenerateShares(int privateKey, int n, int t) {
        // Polynomial coefficients: privateKey is the constant term.
        std::vector<int> coefficients(t);
        coefficients[0] = privateKey;

        // Generate random coefficients for the polynomial (degree t-1)
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 100);

        for (int i = 1; i < t; i++) {
            coefficients[i] = dis(gen);
        }

        // Generate shares (x, f(x))
        std::vector<std::pair<int, int>> shares;
        for (int i = 1; i <= n; i++) {
            int x = i;
            int y = evaluatePolynomial(coefficients, x);
            shares.emplace_back(x, y);
            std::cout << "Share " << i << ": (" << x << ", " << y << ")" << std::endl;
        }

        return shares;
    }

    // Generate random coefficients for the polynomial
    std::vector<BIGNUM_ptr> generateCoefficients(int threshold, const BIGNUM* privateKey, BN_CTX* ctx) {
        std::vector<BIGNUM_ptr> coefficients;
        coefficients.push_back(BIGNUM_ptr(BN_dup(privateKey))); // Constant term is the private key

        for (int i = 1; i < threshold; i++) {
            BIGNUM_ptr coeff(BN_new());
            if (!BN_rand(coeff.get(), 256, 0, 0)) {
                throw std::runtime_error("Failed to generate random coefficient");
            }
            coefficients.push_back(std::move(coeff));
        }
        return coefficients;
    }


    // Evaluate polynomial at a given x using Horner's method
    BIGNUM_ptr evaluatePolynomial(const std::vector<BIGNUM_ptr>& coefficients, int x, BN_CTX* ctx) {
        BIGNUM_ptr result(BN_new());
        BIGNUM_ptr xBn(BN_new());
        BIGNUM_ptr temp(BN_new());

        BN_set_word(xBn.get(), x);
        BN_zero(result.get());

        for (int i = coefficients.size() - 1; i >= 0; i--) {
            BN_mul(result.get(), result.get(), xBn.get(), ctx);     // result = result * x
            BN_add(result.get(), result.get(), coefficients[i].get()); // result += coeff[i]
        }

        return result;
    }
    // Generate shares as BIGNUMs
    std::vector<BIGNUM_ptr> generateShares(const BIGNUM* privateKey, int n, int threshold) {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

        std::vector<BIGNUM_ptr> shares;

        try {
            // Step 1: Generate polynomial coefficients
            std::vector<BIGNUM_ptr> coefficients = generateCoefficients(threshold, privateKey, ctx);

            // Step 2: Generate shares by evaluating the polynomial at x = 1, 2, ..., n
            for (int i = 1; i <= n; i++) {
                shares.push_back(evaluatePolynomial(coefficients, i, ctx));
            }

        }
        catch (...) {
            BN_CTX_free(ctx);
            throw;
        }

        BN_CTX_free(ctx);
        return shares;
    }

}