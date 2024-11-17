#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <random>

#include "keygen.h"

namespace keygen {
    int generateTestKey() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 10000);

        int privateKey = dis(gen);
        std::cout << "Generated Private Key: " << privateKey << std::endl;
        return privateKey;
    }

    bool generateKeyPair(std::string& privateKeyPem, std::string& publicKeyPem) {
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_CTX* ctx = nullptr;
        BIO* privateBio = nullptr;
        BIO* publicBio = nullptr;

        bool success = false;

        do {
            // Step 1: Create a context for key generation
            ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
            if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
                std::cerr << "Error: Failed to create or initialize key generation context." << std::endl;
                break;
            }

            // Step 2: Set the curve (e.g., prime256v1/NIST P-256)
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
                std::cerr << "Error: Failed to set EC curve." << std::endl;
                break;
            }

            // Step 3: Generate the key pair
            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                std::cerr << "Error: Failed to generate EC key pair." << std::endl;
                break;
            }

            // Step 4: Convert private key to PEM format
            privateBio = BIO_new(BIO_s_mem());
            if (!privateBio || !PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
                std::cerr << "Error: Failed to write private key to PEM format." << std::endl;
                break;
            }

            char* privateData = nullptr;
            long privateLen = BIO_get_mem_data(privateBio, &privateData);
            privateKeyPem.assign(privateData, privateLen);

            // Step 5: Convert public key to PEM format
            publicBio = BIO_new(BIO_s_mem());
            if (!publicBio || !PEM_write_bio_PUBKEY(publicBio, pkey)) {
                std::cerr << "Error: Failed to write public key to PEM format." << std::endl;
                break;
            }

            char* publicData = nullptr;
            long publicLen = BIO_get_mem_data(publicBio, &publicData);
            publicKeyPem.assign(publicData, publicLen);

            success = true;

        } while (false);

        // Clean up resources
        if (ctx) EVP_PKEY_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        if (privateBio) BIO_free(privateBio);
        if (publicBio) BIO_free(publicBio);

        return success;
    }

    BIGNUM_ptr generatePrivateKey() {
        BIGNUM_ptr privateKey(BN_new());
        if (!BN_rand(privateKey.get(), 256, 0, 0)) {
            throw std::runtime_error("Failed to generate private key");
        }
        return privateKey;
    }

    BIGNUM_ptr getPublicKey(const BIGNUM* privateKey) {
        EC_GROUP* group = nullptr;
        EC_POINT* pubKeyPoint = nullptr;
        BIGNUM_ptr publicKeyBn(BN_new());

        try {
            // Step 1: Create a new EC group for the curve (NIST P-256)
            group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            if (!group) throw std::runtime_error("Failed to create EC group");

            // Step 2: Compute the public key point (Q = d * G)
            pubKeyPoint = EC_POINT_new(group);
            if (!pubKeyPoint || !EC_POINT_mul(group, pubKeyPoint, privateKey, nullptr, nullptr, nullptr)) {
                throw std::runtime_error("Failed to compute public key point");
            }

            // Step 3: Convert the public key point to an octet string
            size_t pubKeyLen = EC_POINT_point2oct(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
            if (pubKeyLen == 0) throw std::runtime_error("Failed to get public key length");

            std::vector<unsigned char> pubKeyBuffer(pubKeyLen);
            if (!EC_POINT_point2oct(group, pubKeyPoint, POINT_CONVERSION_UNCOMPRESSED, pubKeyBuffer.data(), pubKeyLen, nullptr)) {
                throw std::runtime_error("Failed to encode public key point");
            }

            // Step 4: Convert the binary public key to a BIGNUM
            BN_bin2bn(pubKeyBuffer.data(), pubKeyLen, publicKeyBn.get());
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            publicKeyBn.reset(); // Reset BIGNUM in case of failure
        }

        // Clean up
        if (pubKeyPoint) EC_POINT_free(pubKeyPoint);
        if (group) EC_GROUP_free(group);

        return publicKeyBn;
    }

}