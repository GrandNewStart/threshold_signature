#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <vector>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdexcept>

#include "threshold_crypto_cuda.h"
#include "threshold_crypto.h"

// Kernel to evaluate the polynomial at a given x for all shares
__global__ void evaluatePolynomialKernel(
    int n, 
    int t, 
    unsigned long long* coefficients, 
    unsigned long long* xs, 
    unsigned long long* ys, 
    unsigned long long mod
) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;

    if (idx < n) {
        unsigned long long x = xs[idx];
        unsigned long long result = 0;
        unsigned long long xPow = 1;

        for (int i = 0; i < t; ++i) {
            result = (result + coefficients[i] * xPow) % mod;
            xPow = (xPow * x) % mod;
        }

        ys[idx] = result;
    }
}

std::vector<BIGNUM*> generatePolynomial(const BIGNUM* secret, int t) {
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


// Function to split the private key into shares
std::vector<std::pair<BIGNUM*, BIGNUM*>> generateSharesCUDA(const BIGNUM* privateKey, int n, int t, const BIGNUM* mod) {
    std::vector<BIGNUM*> coefficients = generatePolynomial(privateKey, t); // Assuming generatePolynomial is defined
    unsigned long long* h_coefficients, * h_xs, * h_ys;
    unsigned long long* d_coefficients, * d_xs, * d_ys;

    // Convert coefficients to device-friendly format
    h_coefficients = new unsigned long long[t];
    for (int i = 0; i < t; ++i) {
        h_coefficients[i] = BN_get_word(coefficients[i]);
    }

    // Allocate memory
    cudaMalloc(&d_coefficients, t * sizeof(unsigned long long));
    cudaMalloc(&d_xs, n * sizeof(unsigned long long));
    cudaMalloc(&d_ys, n * sizeof(unsigned long long));

    // Transfer coefficients to the device
    cudaMemcpy(d_coefficients, h_coefficients, t * sizeof(unsigned long long), cudaMemcpyHostToDevice);

    // Initialize x values on host
    h_xs = new unsigned long long[n];
    for (int i = 0; i < n; ++i) {
        h_xs[i] = i + 1; // x values are 1 to n
    }
    cudaMemcpy(d_xs, h_xs, n * sizeof(unsigned long long), cudaMemcpyHostToDevice);

    // Launch kernel to evaluate polynomial
    int blockSize = 256;
    int gridSize = (n + blockSize - 1) / blockSize;
    evaluatePolynomialKernel << <gridSize, blockSize >> > (n, t, d_coefficients, d_xs, d_ys, BN_get_word(mod));

    // Copy results back to host
    h_ys = new unsigned long long[n];
    cudaMemcpy(h_ys, d_ys, n * sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    // Generate shares and public keys
    std::vector<std::pair<BIGNUM*, BIGNUM*>> shares;
    for (int i = 0; i < n; ++i) {
        BIGNUM* y = BN_new();
        BN_set_word(y, h_ys[i]);
        BIGNUM* publicKey = generatePublicKey(y);
        shares.push_back({ y, publicKey });
    }

    // Free memory
    delete[] h_coefficients;
    delete[] h_xs;
    delete[] h_ys;
    cudaFree(d_coefficients);
    cudaFree(d_xs);
    cudaFree(d_ys);

    return shares;
}



__device__ unsigned long long modInverse(unsigned long long a, unsigned long long mod) {
    unsigned long long m0 = mod, t, q;
    unsigned long long x0 = 0, x1 = 1;

    if (mod == 1) return 0;

    while (a > 1) {
        // q is the quotient
        q = a / mod;
        t = mod;

        // m is the remainder now, process the next step
        mod = a % mod, a = t;
        t = x0;

        // Update x0 and x1
        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < 0)
        x1 += m0;

    return x1;
}


__global__ void lagrangeInterpolationKernel(int numShares, unsigned long long* xs, unsigned long long* ys, unsigned long long* results, unsigned long long mod) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;

    if (idx < numShares) {
        unsigned long long lambda = 1;

        for (int j = 0; j < numShares; ++j) {
            if (j == idx) continue;

            unsigned long long denom = (xs[j] - xs[idx] + mod) % mod;
            denom = modInverse(denom, mod); // Modular inverse

            lambda = (lambda * xs[j] % mod * denom % mod) % mod;
        }

        results[idx] = (lambda * ys[idx]) % mod;
    }
}

// Host function for Lagrange interpolation
std::pair<BIGNUM*, BIGNUM*> reconstructKeyCUDA(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& shares, const BIGNUM* mod) {
    int numShares = shares.size();
    unsigned long long* h_xs, * h_ys, * h_results;
    unsigned long long* d_xs, * d_ys, * d_results;

    h_xs = new unsigned long long[numShares];
    h_ys = new unsigned long long[numShares];
    h_results = new unsigned long long[numShares];

    for (int i = 0; i < numShares; ++i) {
        h_xs[i] = BN_get_word(shares[i].first);
        h_ys[i] = BN_get_word(shares[i].second);
    }

    cudaMalloc(&d_xs, numShares * sizeof(unsigned long long));
    cudaMalloc(&d_ys, numShares * sizeof(unsigned long long));
    cudaMalloc(&d_results, numShares * sizeof(unsigned long long));

    cudaMemcpy(d_xs, h_xs, numShares * sizeof(unsigned long long), cudaMemcpyHostToDevice);
    cudaMemcpy(d_ys, h_ys, numShares * sizeof(unsigned long long), cudaMemcpyHostToDevice);

    int blockSize = 256;
    int gridSize = (numShares + blockSize - 1) / blockSize;
    lagrangeInterpolationKernel << <gridSize, blockSize >> > (numShares, d_xs, d_ys, d_results, BN_get_word(mod));

    cudaMemcpy(h_results, d_results, numShares * sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    unsigned long long secret = 0;
    for (int i = 0; i < numShares; ++i) {
        secret = (secret + h_results[i]) % BN_get_word(mod);
    }

    BIGNUM* reconstructedSecret = BN_new();
    BN_set_word(reconstructedSecret, secret);
    BIGNUM* publicKey = generatePublicKey(reconstructedSecret);

    delete[] h_xs;
    delete[] h_ys;
    delete[] h_results;
    cudaFree(d_xs);
    cudaFree(d_ys);
    cudaFree(d_results);

    return { reconstructedSecret, publicKey };
}