#include <iostream>
#include <vector>
#include <random>

#include "secretshare.h"

// y = a0 + a1 x + a2 x^2 + a3 x^3 + a4 x^4 + ... at-1 x^t-1
int evaluatePolynomial(const std::vector<int>& coefficients, int x) {
    int result = 0;
    int power = 1;

    for (int coeff : coefficients) {
        result += coeff * power;
        power *= x;
    }

    return result;
}

std::vector<std::pair<int, int>> generateShares(int privateKey, int n, int t) {
    // Polynomial coefficients: privateKey is the constant term.
    std::vector<int> coefficients(t);
    coefficients[0] = privateKey;

    // Generate random coefficients for the polynomial (degree t-1)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 100);

    for (int i = 1; i < t; i++) {
        coefficients[i] = dis(gen);
    }

    // Generate shares (x, f(x))
    std::vector<std::pair<int, int>> shares;
    for (int i = 1; i <= n; i++) {
        int x = i;
        int y = evaluatePolynomial(coefficients, x);
        shares.emplace_back(x, y);
        std::cout << "Share " << i << ": (" << x << ", " << y << ")" << std::endl;
    }

    return shares;
}