#include "gen_shares.h"
#include "gen_coef.h"
#include "common.h"

#include <chrono> 

int evaluatePolynomial_int(const std::vector<int>& coefficients, int secret, int x, int mod) {
    int y = secret; // Constant term is the secret
    int powerOfX = 1; // x^0 = 1
    for (int coeff : coefficients) {
        powerOfX = (powerOfX * x) % mod; // Compute x^i mod p
        y = (y + coeff * powerOfX) % mod; // Add coeff * x^i mod p
    }
    return y;
}

std::vector<SHARE_INT> generateShares_int(int secret, int n, int t, int mod) {
    if (t > n) {
        throw std::invalid_argument("Threshold t cannot be greater than number of shares n");
    }

    // Generate random coefficients for the polynomial
    auto coefficients = generateCoefficients_int(t - 1, mod);

    // Record start time
    auto start = std::chrono::high_resolution_clock::now();

    // Generate n shares
    std::vector<SHARE_INT> shares;
    for (int i = 1; i <= n; ++i) {
        int x = i; // x-coordinate
        int y = evaluatePolynomial_int(coefficients, secret, x, mod); // Evaluate polynomial at x
        shares.push_back({x,y}); // Add share
    }

    // Record end time
    auto end = std::chrono::high_resolution_clock::now();

    // Estimate process time
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "[generateShares_int] " << duration.count() << " ms" << std::endl;

    return shares;
}

unsigned long long evaluatePolynomial_long(const std::vector<unsigned long long>& coefficients, unsigned long long x, unsigned long long order) {
    unsigned long long result = 0;
    unsigned long long xPow = 1; // x^0 = 1

    for (unsigned long long coeff : coefficients) {
        result = (result + coeff * xPow) % order;
        xPow = (xPow * x) % order; // xPow = x^i
    }

    return result;
}

std::vector<SHARE_LONG> generateShares_long(unsigned long long privateKey, int n, int t, unsigned long long order) {

    // Generate polynomial coefficients
    auto coefficients = generateCoefficients_long(privateKey, t, order);

    // Generate shares
    std::vector<SHARE_LONG> shares;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 1; i <= n; ++i) {
        unsigned long long x = i; // Set x = i

        // Evaluate polynomial at x
        unsigned long long y = evaluatePolynomial_long(coefficients, x, order);

        // Store the share (private key share and public key)
        shares.push_back({ x, y });
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "[generateShares_long] " << duration.count() << " ms" << std::endl;

    return shares;
}

BIGNUM* evaluatePolynomial_BIGNUM(const std::vector<BIGNUM*>& coefficients, const BIGNUM* x, const BIGNUM* order, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* xPow = BN_new();
    BN_one(xPow); // x^0 = 1

    BN_zero(result);
    for (const BIGNUM* coeff : coefficients) {
        BN_mod_mul(temp, coeff, xPow, order, ctx); // temp = coeff * xPow mod order
        BN_mod_add(result, result, temp, order, ctx); // result += temp mod order
        BN_mod_mul(xPow, xPow, x, order, ctx); // xPow = xPow * x mod order
    }

    BN_free(temp);
    BN_free(xPow);
    return result;
}

std::vector<SHARE_BIGNUM> generateShares_BIGNUM(const BIGNUM* privateKey, int n, int t) {
    // Create elliptic curve group for P-256
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        throw std::runtime_error("Failed to create EC_GROUP for P-256");
    }

    // Get the order of the curve group (used as the modulus)
    const BIGNUM* order = EC_GROUP_get0_order(group);
    if (!order) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to get curve group order");
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // Generate polynomial coefficients
    auto coefficients = generateCoefficients_BIGNUM(privateKey, t);

    // Generate shares
    std::vector<SHARE_BIGNUM> shares;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 1; i <= n; ++i) {
        BIGNUM* x = BN_new();
        BN_set_word(x, i); // Set x = i

        // Evaluate polynomial at x
        BIGNUM* y = evaluatePolynomial_BIGNUM(coefficients, x, order, ctx);

        // Store the share (private key share and public key)
        shares.push_back({ x, y });
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "[generateShares_BIGNUM] " << duration.count() << " ms" << std::endl;

    // Free polynomial coefficients
    for (BIGNUM* coeff : coefficients) {
        BN_free(coeff);
    }

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return shares;
}