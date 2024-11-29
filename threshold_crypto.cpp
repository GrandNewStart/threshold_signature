#include "threshold_crypto.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    for (unsigned char byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::string bignumToHex(const BIGNUM* bn) {
    if (!bn) {
        throw std::runtime_error("Invalid BIGNUM");
    }
    char* hex = BN_bn2hex(bn);
    if (!hex) {
        throw std::runtime_error("Failed to convert BIGNUM to hex");
    }
    std::string hexStr(hex);
    OPENSSL_free(hex);
    return hexStr;
}

std::string bufferToHex(const unsigned char* buffer, size_t len) {
    std::string hex;
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", buffer[i]);
        hex.append(buf);
    }
    return hex;
}

std::string sha256(const std::string& message) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    // Create and initialize the context
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create OpenSSL EVP context");
    }

    // Initialize the hashing context with SHA-256
    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Update the hash with the message
    if (EVP_DigestUpdate(context, message.c_str(), message.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Finalize the hash and get the result
    if (EVP_DigestFinal_ex(context, hash, &hash_length) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Clean up the context
    EVP_MD_CTX_free(context);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::pair<BIGNUM*, BIGNUM*> generateKeyPair() {
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

        // Extract public key as BIGNUM (compressed or uncompressed point)
        unsigned char publicKeyBuffer[256];
        size_t publicKeyLen = sizeof(publicKeyBuffer);
        if (EVP_PKEY_get_octet_string_param(pkey, "pub", publicKeyBuffer, publicKeyLen, &publicKeyLen) <= 0) {
            throw std::runtime_error("Failed to extract public key");
        }

        // Convert public key to BIGNUM
        BIGNUM* publicKey = BN_bin2bn(publicKeyBuffer, publicKeyLen, nullptr);
        if (!publicKey) {
            throw std::runtime_error("Failed to convert public key to BIGNUM");
        }

        // Clean up and return keys
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return { privateKey, publicKey };
    }
    catch (...) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw; // Re-throw exception for the caller to handle
    }
}

// Generate public key from a private key share
BIGNUM* generatePublicKey(const BIGNUM* privateKey) {
    BN_CTX* ctx = BN_CTX_new();

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // P-256
    if (!group) {
        throw std::runtime_error("Failed to create EC_GROUP for P-256");
    }

    EC_POINT* publicKeyPoint = EC_POINT_new(group);
    if (!publicKeyPoint) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create EC_POINT");
    }

    if (!EC_POINT_mul(group, publicKeyPoint, privateKey, nullptr, nullptr, ctx)) {
        EC_POINT_free(publicKeyPoint);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to compute public key");
    }

    // Convert public key to octet string
    unsigned char publicKeyBuffer[256];
    size_t publicKeyLen = EC_POINT_point2oct(group, publicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, publicKeyBuffer, sizeof(publicKeyBuffer), ctx);
    if (publicKeyLen == 0) {
        EC_POINT_free(publicKeyPoint);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to convert public key to octet string");
    }

    // Convert public key octet string to BIGNUM
    BIGNUM* publicKey = BN_bin2bn(publicKeyBuffer, publicKeyLen, nullptr);

    EC_POINT_free(publicKeyPoint);
    EC_GROUP_free(group);
    return publicKey;
}


std::vector<BIGNUM*> generatePolynomial(const BIGNUM* secret, int t, BN_CTX* ctx) {
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

// Evaluate polynomial at a given x
BIGNUM* evaluatePolynomial(const std::vector<BIGNUM*>& coefficients, const BIGNUM* x, const BIGNUM* order, BN_CTX* ctx) {
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

// Split the private key into n shares and generate corresponding public keys
std::vector<std::pair<BIGNUM*, BIGNUM*>> generateShares(const BIGNUM* privateKey, int n, int t) {
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
    auto coefficients = generatePolynomial(privateKey, t, ctx);

    // Generate shares
    std::vector<std::pair<BIGNUM*, BIGNUM*>> shares;
    for (int i = 1; i <= n; ++i) {
        BIGNUM* x = BN_new();
        BN_set_word(x, i); // Set x = i

        // Evaluate polynomial at x
        BIGNUM* y = evaluatePolynomial(coefficients, x, order, ctx);

        // Generate public key for this share
        BIGNUM* publicKey = generatePublicKey(y);

        // Store the share (private key share and public key)
        shares.push_back({ y, publicKey });
        BN_free(x);
    }

    // Free polynomial coefficients
    for (BIGNUM* coeff : coefficients) {
        BN_free(coeff);
    }

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return shares;
}

// Reconstruct the private key using Lagrange interpolation
std::pair<BIGNUM*, BIGNUM*> reconstructKeyPair(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& shares) {
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
            const BIGNUM* x_i = shares[i].first;
            const BIGNUM* y_i = shares[i].second;

            BN_one(lambda); // Initialize Lagrange coefficient = 1

            for (size_t j = 0; j < shares.size(); ++j) {
                if (i == j) continue;

                const BIGNUM* x_j = shares[j].first;

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

        // Generate the public key from the reconstructed private key
        EC_POINT* publicKeyPoint = EC_POINT_new(group);
        if (!publicKeyPoint) {
            throw std::runtime_error("Failed to create EC_POINT for public key");
        }

        if (!EC_POINT_mul(group, publicKeyPoint, secret, nullptr, nullptr, ctx)) {
            EC_POINT_free(publicKeyPoint);
            throw std::runtime_error("Failed to compute public key");
        }

        // Convert public key point to uncompressed octet string
        unsigned char publicKeyBuffer[256];
        size_t publicKeyLen = EC_POINT_point2oct(group, publicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, publicKeyBuffer, sizeof(publicKeyBuffer), ctx);
        if (publicKeyLen == 0) {
            EC_POINT_free(publicKeyPoint);
            throw std::runtime_error("Failed to convert public key to octet string");
        }

        // Convert public key to BIGNUM
        publicKey = BN_bin2bn(publicKeyBuffer, publicKeyLen, nullptr);
        if (!publicKey) {
            EC_POINT_free(publicKeyPoint);
            throw std::runtime_error("Failed to convert public key to BIGNUM");
        }

        // Clean up
        EC_POINT_free(publicKeyPoint);
        EC_GROUP_free(group);
        BN_free(temp);
        BN_free(denom);
        BN_free(lambda);
        BN_CTX_free(ctx);

        return { secret, publicKey };
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