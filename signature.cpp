#include <vector>
#include <utility>
#include <string>
#include <iostream>

#include "signature.h"
#include "hash.h"

// Each participant generates a partial signature
int generatePartialSignature(int share, const std::string& hash) {
    // Convert hash to integer (simple approach by summing ASCII values)
    int hashInt = 0;
    for (char c : hash) {
        hashInt += static_cast<int>(c);
    }

    // Simulate partial signing (hash * share)
    int partialSignature = hashInt * share;
    return partialSignature;
}

// Function to calculate the Lagrange coefficient for a given x
double lagrangeCoefficient(int x, const std::vector<int>& xValues) {
    double result = 1.0;

    for (int xi : xValues) {
        if (xi != x) {
            result *= static_cast<double>(0 - xi) / (x - xi);
        }
    }

    return result;
}

int aggregateSignatures(const std::vector<std::pair<int, int>>& partialSignatures) {
    int finalSignature = 0;

    // Extract x-values from partial signatures
    std::vector<int> xValues;
    for (const auto& [x, sig] : partialSignatures) {
        xValues.push_back(x);
    }

    // Aggregate partial signatures using Lagrange interpolation
    for (const auto& [x, sig] : partialSignatures) {
        double coefficient = lagrangeCoefficient(x, xValues);
        finalSignature += static_cast<int>(coefficient * sig);
    }

    return finalSignature;
}

bool verifySignature(int finalSignature, const std::string& message, int privateKey) {
    std::string messageHash = sha256(message);

    // Convert message hash to an integer
    int hashInt = 0;
    for (char c : messageHash) {
        hashInt += static_cast<int>(c);
    }

    // Calculate expected signature using private key and hash
    int expectedSignature = hashInt * privateKey;
    std::cout << "Expected Signature: " << expectedSignature << std::endl;
    std::cout << "Final Signature: " << finalSignature << std::endl;

    return finalSignature == expectedSignature;
}