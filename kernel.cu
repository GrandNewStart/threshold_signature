#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <iostream>
#include <vector>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "threshold_crypto.h"
#include "threshold_crypto_cuda.h"

void printKeyPair(std::pair<BIGNUM*, BIGNUM*> keyPair) {
    char* privHex1 = BN_bn2hex(keyPair.first);
    std::cout << "Private Key: " << privHex1 << std::endl;
    OPENSSL_free(privHex1);

    char* pubHex1 = BN_bn2hex(keyPair.second);
    std::cout << "Public Key: " << pubHex1 << std::endl;
    OPENSSL_free(pubHex1);
}

void printShares(std::vector<std::pair<BIGNUM*, BIGNUM*>> shares) {
    for (auto& share : shares) {
        std::cout << "share: " << share.first << ", " << share.second << std::endl;
    }
}

void test_aggregate_key() {
    try {
        // Generate key pair
        std::pair<BIGNUM*, BIGNUM*> keyPair = generateKeyPair();
        printKeyPair(keyPair);

        // Generate 100 shares with a threshold of 50
        int n = 5, t = 3;
        std::vector<std::pair<BIGNUM*, BIGNUM*>> shares = generateShares(keyPair.first, n, t);
        printShares(shares);

        // Reconstruct the original key pair from shares
        std::pair<BIGNUM*, BIGNUM*> reconstructed = reconstructKeyPair(shares);
        printKeyPair(reconstructed);

        if (BN_cmp(keyPair.first, reconstructed.first) != 0) {
            std::cerr << "Private keys do not match!" << std::endl;
        }
        else {
            std::cout << "Private keys match!" << std::endl;
        }
        if (BN_cmp(keyPair.second, reconstructed.second) != 0) {
            std::cerr << "Public keys do not match!" << std::endl;
        }
        else {
            std::cout << "Public keys match!" << std::endl;
        }

        // Clean up
        for (auto& share : shares) {
            BN_free(share.first); // Free private share
            BN_free(share.second); // Free public key
        }

        BN_free(keyPair.first);
        BN_free(keyPair.second);

        BN_free(reconstructed.first);
        BN_free(reconstructed.second);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

}

void test_aggregate_key_cuda() {
    try {
        // Generate key pair
        std::pair<BIGNUM*, BIGNUM*> keyPair = generateKeyPair();
        printKeyPair(keyPair);

        // Number of shares and threshold
        int n = 5, t = 3;

        // Get the elliptic curve group and modulus
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group) {
            throw std::runtime_error("Failed to create EC_GROUP for P-256");
        }
        const BIGNUM* mod = EC_GROUP_get0_order(group);
        if (!mod) {
            throw std::runtime_error("Failed to get curve group order");
        }

        // Generate shares using CUDA
        std::vector<std::pair<BIGNUM*, BIGNUM*>> shares = generateSharesCUDA(keyPair.first, n, t, mod);
        printShares(shares);

        // Convert shares for reconstruction
        std::vector<std::pair<BIGNUM*, BIGNUM*>> sharesVector;
        for (const auto& share : shares) {
            sharesVector.push_back({ share.first, share.second });
        }

        // Reconstruct the original key pair using CUDA
        std::pair<BIGNUM*, BIGNUM*> reconstructed = reconstructKeyCUDA(sharesVector, mod);
        printKeyPair(reconstructed);

        // Validate the reconstructed keys
        if (BN_cmp(keyPair.first, reconstructed.first) != 0) {
            std::cerr << "Private keys do not match!" << std::endl;
        }
        else {
            std::cout << "Private keys match!" << std::endl;
        }
        if (BN_cmp(keyPair.second, reconstructed.second) != 0) {
            std::cerr << "Public keys do not match!" << std::endl;
        }
        else {
            std::cout << "Public keys match!" << std::endl;
        }

        // Clean up
        for (auto& share : shares) {
            BN_free(share.first);  // Free private share
            BN_free(share.second); // Free public key
        }

        BN_free(keyPair.first);
        BN_free(keyPair.second);

        BN_free(reconstructed.first);
        BN_free(reconstructed.second);

        EC_GROUP_free(group);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main()
{
    //test_aggregate_key();
    test_aggregate_key_cuda();
    return 0;
}
