#include <vector>
#include <utility>
#include <string>
#include <iostream>

#include "keygen.h"
#include "secretshare.h"
#include "bignum.h"
#include "hash.h"
#include "signature.h"

using namespace keygen;
using namespace secretshare;

void test() {
    int n = 5;
    int t = 3;

    int privateKey = generateTestKey();

    std::vector<std::pair<int, int>> shares = testGenerateShares(privateKey, n, t);

    std::string message = "Hello, threshold signature!";
    std::vector<std::pair<int, int>> partialSignatures;
    for (const auto& [x, share] : shares) {
        int partialSignature = generatePartialSignature(share, sha256(message));
        partialSignatures.emplace_back(x, partialSignature);
    }
    int finalSignature = aggregateSignatures(partialSignatures);

    bool isValid = verifySignature(finalSignature, message, privateKey);
    std::cout << "Verification result: " << (isValid ? "Valid" : "Invalid") << std::endl;
}

void test2() {
    int n = 100;
    int t = 50;

    std::string privateKeyPem, publicKeyPem;
    if (generateKeyPair(privateKeyPem, publicKeyPem)) {
        std::cout << "ECDSA Key Pair Generated Successfully!" << std::endl;
        std::cout << "Private Key (PEM):\n" << privateKeyPem << std::endl;
        std::cout << "Public Key (PEM):\n" << publicKeyPem << std::endl;
    }
    else {
        std::cerr << "Failed to generate ECDSA key pair." << std::endl;
    }
}

void keygen_test() {
    try {
        BIGNUM_ptr privateKey = generatePrivateKey();
        BIGNUM_ptr publicKey = getPublicKey(privateKey.get());
        std::cout << "Private Key: " << BN_bn2hex(privateKey.get()) << std::endl;
        std::cout << "Public Key: " << BN_bn2hex(publicKey.get()) << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void secretshare_test() {
    try {
        BIGNUM_ptr privateKey = generatePrivateKey();
        BIGNUM_ptr publicKey = getPublicKey(privateKey.get());
        std::cout << "Private Key: " << BN_bn2hex(privateKey.get()) << std::endl;
        std::cout << "Public Key: " << BN_bn2hex(publicKey.get()) << std::endl;

        int n = 100;
        int t = 50;
        std::vector<BIGNUM_ptr> shares = generateShares(privateKey.get(), n, t);

        std::cout << "\nShares:" << std::endl;
        for (size_t i = 0; i < shares.size(); i++) {
            BIGNUM_ptr pub = getPublicKey(shares[i].get());
            std::cout << "Share " << i + 1 << ": " << BN_bn2hex(shares[i].get()) << ", " << BN_bn2hex(pub.get()) << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    secretshare_test();
}

