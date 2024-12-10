#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include "recon_key_cuda.h"

__global__ void lagrangeInterpolationKernel_int(int* xs, int* ys, int* results, int numShares, int mod) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < numShares) {
        int xi = xs[idx];
        int yi = ys[idx];
        int li = 1;

        // Compute Lagrange basis polynomial L_i(0)
        for (int j = 0; j < numShares; ++j) {
            if (j == idx) continue;

            int xj = xs[j];
            int numerator = xj;
            int denominator = (xj - xi + mod) % mod;

            // Compute modular inverse of denominator
            int denomInv = 1;
            for (int k = 1; k < mod; ++k) { // Brute-force modular inverse
                if ((denominator * k) % mod == 1) {
                    denomInv = k;
                    break;
                }
            }

            li = (li * numerator % mod * denomInv % mod) % mod;
        }

        // Compute contribution to the final secret
        results[idx] = (yi * li % mod);
    }
}

int reconstructKey_int_CUDA(const std::vector<SHARE_INT>& shares, int mod) {
    int numShares = shares.size();

    // Allocate memory on the device
    int* d_xs;
    int* d_ys;
    int* d_results;
    cudaMalloc(&d_xs, numShares * sizeof(int));
    cudaMalloc(&d_ys, numShares * sizeof(int));
    cudaMalloc(&d_results, numShares * sizeof(int));

    // Copy shares to the device
    std::vector<int> xs(numShares), ys(numShares);
    for (int i = 0; i < numShares; ++i) {
        xs[i] = shares[i].x;
        ys[i] = shares[i].y;
    }
    cudaMemcpy(d_xs, xs.data(), numShares * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_ys, ys.data(), numShares * sizeof(int), cudaMemcpyHostToDevice);

    // Start timing using CUDA events
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    // Configure and launch the kernel
    int blockSize = 256;
    int gridSize = (numShares + blockSize - 1) / blockSize;
    cudaEventRecord(start);
    lagrangeInterpolationKernel_int << <gridSize, blockSize >> > (d_xs, d_ys, d_results, numShares, mod);
    cudaEventRecord(stop);

    // Wait for the GPU to finish
    cudaEventSynchronize(stop);

    // Calculate the elapsed time
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);

    // Print the timing result
    std::cout << "[reconstructKey_int_CUDA] " << milliseconds << " ms" << std::endl;

    // Destroy CUDA events
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Copy results back to the host
    std::vector<int> results(numShares);
    cudaMemcpy(results.data(), d_results, numShares * sizeof(int), cudaMemcpyDeviceToHost);

    // Aggregate contributions to reconstruct the secret
    int secret = 0;
    for (int r : results) {
        secret = (secret + r) % mod;
    }

    // Free device memory
    cudaFree(d_xs);
    cudaFree(d_ys);
    cudaFree(d_results);

    return secret;
}

__device__ unsigned long long modInverse_long_device(unsigned long long a, unsigned long long mod) {
    unsigned long long m0 = mod, t, q;
    unsigned long long x0 = 0, x1 = 1;

    if (mod == 1) return 0;

    while (a > 1) {
        q = a / mod;
        t = mod;

        mod = a % mod;
        a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

__global__ void lagrangeInterpolationKernel_long(
    int numShares,
    unsigned long long* xs,
    unsigned long long* ys,
    unsigned long long* results,
    unsigned long long mod
) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;

    if (idx < numShares) {
        unsigned long long lambda = 1;

        for (int j = 0; j < numShares; ++j) {
            if (j == idx) continue;

            // Compute denominator
            unsigned long long denom = (xs[j] - xs[idx] + mod) % mod;
            if (denom == 0) {
                printf("Thread %d: Denom is zero for j = %d, xs[j] = %llu, xs[idx] = %llu\n", idx, j, xs[j], xs[idx]);
                return; // Skip if invalid denom
            }

            // Compute modular inverse
            unsigned long long denomInv = modInverse_long_device(denom, mod);
            if (denomInv == 0) {
                printf("Thread %d: modInverse failed for denom = %llu\n", idx, denom);
                return; // Skip if modular inverse fails
            }

            // Update lambda
            unsigned long long oldLambda = lambda;
            lambda = (lambda % mod * xs[j] % mod * denomInv % mod) % mod;

            // Log intermediate values
            //printf("Thread %d: j = %d, denom = %llu, denomInv = %llu, oldLambda = %llu, lambda = %llu\n",
            //    idx, j, denom, denomInv, oldLambda, lambda);
        }

        // Compute result
        results[idx] = (lambda * ys[idx]) % mod;

        // Log final result
        //printf("Thread %d: final lambda = %llu, result = %llu\n", idx, lambda, results[idx]);
    }
}

unsigned long long reconstructKey_long_CUDA(const std::vector<SHARE_LONG>& shares, unsigned long long order) {
    int numShares = shares.size();
    unsigned long long* h_xs, * h_ys, * h_results;
    unsigned long long* d_xs, * d_ys, * d_results;

    h_xs = new unsigned long long[numShares];
    h_ys = new unsigned long long[numShares];
    h_results = new unsigned long long[numShares];

    for (int i = 0; i < numShares; ++i) {
        h_xs[i] = shares[i].x;
        h_ys[i] = shares[i].y;
    }

    cudaMalloc(&d_xs, numShares * sizeof(unsigned long long));
    cudaMalloc(&d_ys, numShares * sizeof(unsigned long long));
    cudaMalloc(&d_results, numShares * sizeof(unsigned long long));

    cudaMemcpy(d_xs, h_xs, numShares * sizeof(unsigned long long), cudaMemcpyHostToDevice);
    cudaMemcpy(d_ys, h_ys, numShares * sizeof(unsigned long long), cudaMemcpyHostToDevice);


    // Start timing using CUDA events
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    int blockSize = 256;
    int gridSize = (numShares + blockSize - 1) / blockSize;
    cudaEventRecord(start);
    lagrangeInterpolationKernel_long << <gridSize, blockSize >> > (numShares, d_xs, d_ys, d_results, order);
    cudaEventRecord(stop);

    // Wait for the GPU to finish
    cudaEventSynchronize(stop);

    // Calculate the elapsed time
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);

    // Print the timing result
    std::cout << "[reconstructKey_int_CUDA] " << milliseconds << " ms" << std::endl;

    // Destroy CUDA events
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    cudaMemcpy(h_results, d_results, numShares * sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    unsigned long long secret = 0;
    for (int i = 0; i < numShares; ++i) {
        secret = (secret + h_results[i]) % order;
    }

    delete[] h_xs;
    delete[] h_ys;
    delete[] h_results;
    cudaFree(d_xs);
    cudaFree(d_ys);
    cudaFree(d_results);

    return secret;
}

BIGNUM* reconstructKey_BIGNUM_CUDA(const std::vector<SHARE_BIGNUM>& shares, const BIGNUM* mod) {
    int numShares = shares.size();
    unsigned long long* h_xs, * h_ys, * h_results;
    unsigned long long* d_xs, * d_ys, * d_results;

    h_xs = new unsigned long long[numShares];
    h_ys = new unsigned long long[numShares];
    h_results = new unsigned long long[numShares];

    for (int i = 0; i < numShares; ++i) {
        h_xs[i] = BN_get_word(shares[i].x);
        h_ys[i] = BN_get_word(shares[i].y);
    }

    cudaMalloc(&d_xs, numShares * sizeof(unsigned long long));
    cudaMalloc(&d_ys, numShares * sizeof(unsigned long long));
    cudaMalloc(&d_results, numShares * sizeof(unsigned long long));

    cudaMemcpy(d_xs, h_xs, numShares * sizeof(unsigned long long), cudaMemcpyHostToDevice);
    cudaMemcpy(d_ys, h_ys, numShares * sizeof(unsigned long long), cudaMemcpyHostToDevice);


    // Start timing using CUDA events
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    int blockSize = 256;
    int gridSize = (numShares + blockSize - 1) / blockSize;
    cudaEventRecord(start);
    lagrangeInterpolationKernel_long << <gridSize, blockSize >> > (numShares, d_xs, d_ys, d_results, BN_get_word(mod));
    cudaEventRecord(stop);

    // Wait for the GPU to finish
    cudaEventSynchronize(stop);

    // Calculate the elapsed time
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);

    // Print the timing result
    std::cout << "[reconstructKey_int_CUDA] " << milliseconds << " ms" << std::endl;

    // Destroy CUDA events
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    cudaMemcpy(h_results, d_results, numShares * sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    unsigned long long secret = 0;
    for (int i = 0; i < numShares; ++i) {
        secret = (secret + h_results[i]) % BN_get_word(mod);
    }

    BIGNUM* reconsestructed = BN_new();
    BN_set_word(reconsestructed, secret);

    delete[] h_xs;
    delete[] h_ys;
    delete[] h_results;
    cudaFree(d_xs);
    cudaFree(d_ys);
    cudaFree(d_results);

    return reconsestructed;
}