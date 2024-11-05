#include <iostream>
#include <vector>

#include "keygen.h"
#include "secretshare.h"
#include "hash.h"
#include "signature.h"

void test1() {
    // Parameters for secret sharing
    int n = 5;    // Total number of shares
    int t = 3;    // Threshold to reconstruct the key

    // Step 1: Generate the private key
    int privateKey = generatePrivateKey();

    // Step 2: Generate shares
    std::vector<std::pair<int, int>> shares = generateShares(privateKey, n, t);

    // Now you have `shares` that can be used for threshold signature implementation
    // Only t shares are needed to reconstruct the key.
}

void test2() {
    // Parameters for secret sharing
    int n = 5;    // Total number of shares
    int t = 3;    // Threshold to reconstruct the key

    // Step 1: Generate the private key
    int privateKey = generatePrivateKey();

    // Step 2: Generate shares
    std::vector<std::pair<int, int>> shares = generateShares(privateKey, n, t);

    // Step 3: Generate partial signatures
    std::string message = "Hello, threshold signature!";
    std::vector<int> partialSignatures = generatePartialSignatures(shares, message);

    // At this point, we have partial signatures from each share
    // These would be used in a later step to aggregate into a final signature
}


int main() {
    test2();
}