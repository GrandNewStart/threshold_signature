#include <iostream>
#include <random>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include "gen_key.h"

int generateKey_int(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    return dis(gen);
}

unsigned long long generateKey_long(unsigned long long mod) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis(1, mod - 1);
    return dis(gen);
}

BIGNUM* generateKey_BIGNUM() {
    // Initialize OpenSSL context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    EVP_PKEY* pkey = nullptr;
    try {
        // Initialize key generation
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            throw std::runtime_error("Failed to initialize key generation");
        }

        // Set the curve to P-256
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
            throw std::runtime_error("Failed to set curve to P-256");
        }

        // Generate the key pair
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            throw std::runtime_error("Failed to generate key pair");
        }

        // Extract private key as BIGNUM
        BIGNUM* privateKey = nullptr;
        if (EVP_PKEY_get_bn_param(pkey, "priv", &privateKey) <= 0) {
            throw std::runtime_error("Failed to extract private key");
        }
        // Clean up and return keys
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        return privateKey;
    }
    catch (...) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw; // Re-throw exception for the caller to handle
    }
}