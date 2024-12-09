#include "recon_key.h"

int modInverse_int(int a, int mod) {
    int m0 = mod, t, q;
    int x0 = 0, x1 = 1;

    if (mod == 1) return 0;

    while (a > 1) {
        // q is quotient
        q = a / mod;
        t = mod;

        // Update mod and a
        mod = a % mod;
        a = t;

        // Update x0 and x1
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < 0) {
        x1 += m0;
    }

    return x1;
}


int reconstructKey_int(const std::vector<SHARE_INT>& shares, int mod) {
    int secret = 0; // Initialize the secret

    // Iterate over each share
    for (size_t i = 0; i < shares.size(); ++i) {
        int xi = shares[i].x;
        int yi = shares[i].y;

        // Compute Lagrange basis polynomial L_i(0)
        int li = 1;
        for (size_t j = 0; j < shares.size(); ++j) {
            if (i == j) continue;

            int xj = shares[j].x;

            // Compute L_i(0) = product (xj / (xj - xi)) mod p
            int numerator = xj; // xj
            int denominator = (xj - xi + mod) % mod; // (xj - xi) mod p

            // Compute modular inverse of denominator
            int denomInv = modInverse_int(denominator, mod);
            if (denomInv == 0) {
                throw std::runtime_error("No modular inverse exists");
            }

            // Update L_i(0)
            li = (li * numerator % mod * denomInv % mod) % mod;
        }

        // Add current term to the secret: yi * L_i(0) mod p
        secret = (secret + yi * li % mod) % mod;
    }

    return secret; // The reconstructed secret
}

unsigned long long modInverse_long(unsigned long long a, unsigned long long mod) {
    unsigned long long m0 = mod, t, q;
    unsigned long long x0 = 0, x1 = 1;

    if (mod == 1) return 0;

    while (a > 1) {
        q = a / mod;
        t = mod;

        mod = a % mod;
        a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

unsigned long long reconstructKey_long(const std::vector<SHARE_LONG>& shares, unsigned long long order) {
    if (shares.size() < 2) {
        throw std::runtime_error("At least two shares are required for reconstruction");
    }

    unsigned long long secret = 0; // Reconstructed private key

    for (size_t i = 0; i < shares.size(); ++i) {
        unsigned long long x_i = shares[i].x;
        unsigned long long y_i = shares[i].y;

        unsigned long long lambda = 1; // Initialize Lagrange coefficient = 1

        for (size_t j = 0; j < shares.size(); ++j) {
            if (i == j) continue;

            unsigned long long x_j = shares[j].x;

            // Compute (x_j - x_i) mod order
            unsigned long long denom = (x_j >= x_i ? x_j - x_i : order + x_j - x_i) % order;


            // Compute modular inverse of the denominator
            unsigned long long denomInv = modInverse_long(denom, order);
            if (denomInv == 0) {
                throw std::runtime_error("Failed to compute modular inverse");
            }

            // Update lambda = lambda * x_j * denom^-1 mod order
            lambda = (lambda * x_j % order * denomInv % order) % order;
        }

        // Multiply lambda by y_i (y-coordinate of the share) and add to secret
        secret = (secret + lambda * y_i % order) % order;
    }

    return secret;
}

BIGNUM* reconstructKey_BIGNUM(const std::vector<SHARE_BIGNUM>& shares) {
    // Ensure that there are at least two shares provided for reconstruction
    if (shares.size() < 2) {
        throw std::runtime_error("At least two shares are required for reconstruction");
    }

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

    // Create a BN_CTX context for temporary operations
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // Initialize variables for Lagrange interpolation
    BIGNUM* secret = BN_new();
    BIGNUM* publicKey = nullptr; // Public key will be generated later
    BN_zero(secret);

    BIGNUM* temp = BN_new();
    BIGNUM* denom = BN_new();
    BIGNUM* lambda = BN_new();

    try {
        for (size_t i = 0; i < shares.size(); ++i) {
            const BIGNUM* x_i = shares[i].x;
            const BIGNUM* y_i = shares[i].y;

            BN_one(lambda); // Initialize Lagrange coefficient = 1

            for (size_t j = 0; j < shares.size(); ++j) {
                if (i == j) continue;

                const BIGNUM* x_j = shares[j].x;

                // Compute (x_j - x_i) mod order
                BN_mod_sub(denom, x_j, x_i, order, ctx); // denom = (x_j - x_i) mod order
                if (BN_is_zero(denom)) {
                    throw std::runtime_error("Duplicate x values detected in shares");
                }

                // Compute modular inverse of the denominator
                if (!BN_mod_inverse(denom, denom, order, ctx)) { // denom = (x_j - x_i)^-1 mod order
                    throw std::runtime_error("Failed to compute modular inverse");
                }

                // Update lambda = lambda * x_j * (x_j - x_i)^-1 mod order
                BN_mod_mul(temp, x_j, denom, order, ctx); // temp = x_j * (x_j - x_i)^-1 mod order
                BN_mod_mul(lambda, lambda, temp, order, ctx); // lambda = lambda * temp mod order
            }

            // Multiply lambda by y_i (y-coordinate of the share)
            BN_mod_mul(lambda, lambda, y_i, order, ctx); // lambda = lambda * y_i mod order

            // Add to the result (mod order)
            BN_mod_add(secret, secret, lambda, order, ctx); // secret = secret + lambda mod order
        }


        // Clean up
        EC_GROUP_free(group);
        BN_free(temp);
        BN_free(denom);
        BN_free(lambda);
        BN_CTX_free(ctx);

        return secret;
    }
    catch (...) {
        // Clean up in case of error
        EC_GROUP_free(group);
        BN_free(secret);
        BN_free(temp);
        BN_free(denom);
        BN_free(lambda);
        BN_CTX_free(ctx);
        throw; // Re-throw the exception
    }
}