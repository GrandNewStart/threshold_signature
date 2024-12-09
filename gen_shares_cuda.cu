#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include "common.h"
#include "gen_coef.h"

__global__ void evaluatePolynomial_int_CUDA(
    int* coefficients, 
    int secret, 
    int* xs, 
    int* ys, 
    int degree, 
    int mod, 
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < n) {
        int x = xs[idx];
        int y = secret;
        int powerOfX = 1;

        // Evaluate the polynomial at x
        for (int i = 0; i < degree; ++i) {
            powerOfX = (powerOfX * x) % mod; // Compute x^i mod p
            y = (y + coefficients[i] * powerOfX) % mod;
        }

        ys[idx] = y; // Store the result
    }
}

std::vector<SHARE_INT> generateShares_int_CUDA(int secret, int n, int t, int mod) {
    if (t > n) {
        throw std::invalid_argument("Threshold t cannot be greater than number of shares n");
    }

    // Generate random coefficients for the polynomial on the host
    auto coefficients = generateCoefficients_int(t - 1, mod);

    // Allocate memory on the device
    int* d_coefficients;
    int* d_xs;
    int* d_ys;
    cudaMalloc(&d_coefficients, (t - 1) * sizeof(int));
    cudaMalloc(&d_xs, n * sizeof(int));
    cudaMalloc(&d_ys, n * sizeof(int));

    // Copy coefficients to the device
    cudaMemcpy(d_coefficients, coefficients.data(), (t - 1) * sizeof(int), cudaMemcpyHostToDevice);

    // Generate x-coordinates on the host
    std::vector<int> xs(n);
    for (int i = 0; i < n; ++i) {
        xs[i] = i + 1; // x = 1, 2, ..., n
    }

    // Copy x-coordinates to the device
    cudaMemcpy(d_xs, xs.data(), n * sizeof(int), cudaMemcpyHostToDevice);

    // Configure and launch the kernel
    int blockSize = 256;
    int gridSize = (n + blockSize - 1) / blockSize;
    evaluatePolynomial_int_CUDA << <gridSize, blockSize >> > (d_coefficients, secret, d_xs, d_ys, t - 1, mod, n);

    // Copy results back to the host
    std::vector<int> ys(n);
    cudaMemcpy(ys.data(), d_ys, n * sizeof(int), cudaMemcpyDeviceToHost);

    // Free device memory
    cudaFree(d_coefficients);
    cudaFree(d_xs);
    cudaFree(d_ys);

    // Combine x- and y-coordinates into shares
    std::vector<SHARE_INT> shares;
    for (int i = 0; i < n; ++i) {
        shares.push_back({ xs[i], ys[i] });
    }

    return shares;
}

__global__ void evaluatePolynomial_long_CUDA(
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


std::vector<SHARE_LONG> generateShares_long_CUDA(unsigned long long privateKey, int n, int t, unsigned long long order) {
    auto coefficients = generateCoefficients_long(privateKey, t, order);
    unsigned long long* h_coefficients, * h_xs, * h_ys;
    unsigned long long* d_coefficients, * d_xs, * d_ys;

    h_coefficients = new unsigned long long[t];
    for (int i = 0; i < t; ++i) {
        h_coefficients[i] = coefficients[i];
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
    evaluatePolynomial_long_CUDA << <gridSize, blockSize >> > (n, t, d_coefficients, d_xs, d_ys, order);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        std::cerr << "CUDA Error: " << cudaGetErrorString(err) << std::endl;
    }

    // Copy results back to host
    h_ys = new unsigned long long[n];
    cudaMemcpy(h_ys, d_ys, n * sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    // Generate shares
    std::vector<SHARE_LONG> shares;
    for (int i = 0; i < n; ++i) {
        shares.push_back({ h_xs[i], h_ys[i] });
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

std::vector<SHARE_BIGNUM> generateShares_BIGNUM_CUDA(const BIGNUM* privateKey, int n, int t, const BIGNUM* mod) {
    std::vector<BIGNUM*> coefficients = generateCoefficients_BIGNUM(privateKey, t); // Assuming generatePolynomial is defined
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
    evaluatePolynomial_long_CUDA << <gridSize, blockSize >> > (n, t, d_coefficients, d_xs, d_ys, BN_get_word(mod));

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        std::cerr << "CUDA Error: " << cudaGetErrorString(err) << std::endl;
    }

    // Copy results back to host
    h_ys = new unsigned long long[n];
    cudaMemcpy(h_ys, d_ys, n * sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    // Generate shares and public keys
    std::vector<SHARE_BIGNUM> shares;
    for (int i = 0; i < n; ++i) {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        BN_set_word(x, h_xs[i]);
        BN_set_word(y, h_ys[i]);
        shares.push_back({ x, y});
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
