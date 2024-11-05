#include <iostream>
#include <vector>
#include <random>

#include "keygen.h"

int generatePrivateKey() {
    // Use a random number generator for simplicity.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 10000);  // Generate a random number between 1 and 10000

    int privateKey = dis(gen);
    std::cout << "Generated Private Key: " << privateKey << std::endl;
    return privateKey;
}