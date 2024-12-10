#include <chrono> 

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include "common.h"
#include "gen_key.h"
#include "gen_shares.h"
#include "gen_shares_cuda.h"
#include "recon_key.h"
#include "recon_key_cuda.h"

bool showLogs = false;
bool showTimes = true;
int n = 1000;
int t = 200;

void test_int() {
    try {
        // Step 1: Generate a random key
        int secret = generateKey_int(1, 100);
        if (showLogs) {
            std::cout << "[test_int] Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        int mod = 101;
        auto start = std::chrono::high_resolution_clock::now();
        auto shares = generateShares_int(secret, n, t, mod);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - start;
        if (showLogs) {
            std::cout << "[test_int] Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }
        if (showTimes) {
            std::cout << "[test_int] share generation time: " << duration.count() << " ms" << std::endl;
        }

        // Step 3: Reconstruct the key from the shares
        std::vector<SHARE_INT> selectedShares(shares.begin(), shares.begin() + t);
        start = std::chrono::high_resolution_clock::now();
        int reconstructed = reconstructKey_int(selectedShares, mod);
        end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        if (showLogs) {
            std::cout << "[test_int] Reconstructed Secret Key: " << reconstructed << std::endl;
        }
        if (showTimes) {
            std::cout << "[test_int] key reconstruction time: " << duration.count() << " ms" << std::endl;
        }

        // Step 4: Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_int] SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_int] FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[test_int] Error: " << e.what() << std::endl;
    }
}


void test_int_cuda() {
    try {
        // Step 1: Generate a random key
        int secret = generateKey_int(1, 100);
        if (showLogs) {
            std::cout << "[test_int_cuda] Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        int mod = 101;
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<SHARE_INT> shares = generateShares_int_CUDA(secret, n, t, mod);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - start;
        if (showLogs) {
            std::cout << "[test_int_cuda] Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }
        if (showTimes) {
            std::cout << "[test_int_cuda] share generation time: " << duration.count() << " ms" << std::endl;
        }
 
        // Step 3: Reconstruct the key from the shares
        start = std::chrono::high_resolution_clock::now();
        int reconstructed = reconstructKey_int_CUDA(shares, mod);
        end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        if (showLogs) {
            std::cout << "[test_int_cuda] Reconstructed Secret Key: " << reconstructed << std::endl;
        }
        if (showTimes) {
            std::cout << "[test_int_cuda] key reconstruction time: " << duration.count() << " ms" << std::endl;
        }

        // Step 4: Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_int_cuda] SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_int_cuda] FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[test_int_cuda] Error: " << e.what() << std::endl;
    }
}

void test_long() {
    try {
        unsigned long long order = 1000000007;

        // Step 1: Generate a random key
        unsigned long long secret = generateKey_long(order);
        if (showLogs) {
            std::cout << "[test_long] Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<SHARE_LONG> shares = generateShares_long(secret, n, t, order);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - start;
        if (showLogs) {
            std::cout << "[test_long] Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }
        if (showTimes) {
            std::cout << "[test_long] share generation time: " << duration.count() << " ms" << std::endl;
        }

        // Step 3: Reconstruct the key from the shares
        start = std::chrono::high_resolution_clock::now();
        unsigned long long reconstructed = reconstructKey_long(shares, order);
        end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        if (showLogs) {
            std::cout << "[test_long] Reconstructed Secret Key: " << reconstructed << std::endl;
        }
        if (showTimes) {
            std::cout << "[test_long] key reconstruction time: " << duration.count() << " ms" << std::endl;
        }

        // Step 4: Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_long] SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_long] FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[test_long] Error: " << e.what() << std::endl;
    }
}

void test_long_cuda() {
    try {
        unsigned long long order = 1000000007;

        // Step 1: Generate a random key
        unsigned long long secret = generateKey_long(order);
        if (showLogs) {
            std::cout << "[test_long_cuda] Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<SHARE_LONG> shares = generateShares_long_CUDA(secret, n, t, order);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - start;
        if (showLogs) {
            std::cout << "[test_long_cuda] Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }
        if (showTimes) {
            std::cout << "[test_long_cuda] share generation time: " << duration.count() << " ms" << std::endl;
        }

        // Step 3: Reconstruct the key from the shares
        start = std::chrono::high_resolution_clock::now();
        unsigned long long reconstructed = reconstructKey_long_CUDA(shares, order);
        end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        if (showLogs) {
            std::cout << "[test_long_cuda] Reconstructed Secret Key: " << reconstructed << std::endl;
        }
        if (showTimes) {
            std::cout << "[test_long_cuda] key reconstruction time: " << duration.count() << " ms" << std::endl;
        }

        // Step 4: Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_long_cuda] SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_long_cuda] FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void test_BIGNUM() {
    try {
        // Step 1: Generate a random key
        BIGNUM* secret = generateKey_BIGNUM();
        if (showLogs) {
            std::cout << "[test_BIGNUM] Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<SHARE_BIGNUM> shares = generateShares_BIGNUM(secret, n, t);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - start;
        if (showLogs) {
            std::cout << "[test_BIGNUM] Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }
        if (showTimes) {
            std::cout << "[test_BIGNUM] share generation time: " << duration.count() << " ms" << std::endl;
        }

        // Step 3: Reconstruct the key from the shares
        start = std::chrono::high_resolution_clock::now();
        BIGNUM* reconstructed = reconstructKey_BIGNUM(shares);
        end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        if (showLogs) {
            std::cout << "[test_BIGNUM] Reconstructed Secret Key: " << reconstructed << std::endl;
        }
        if (showTimes) {
            std::cout << "[test_BIGNUM] key reconstruction time: " << duration.count() << " ms" << std::endl;
        }

        // Step 4: Verify correctness
        if (BN_cmp(secret, reconstructed) != 0) {
            std::cout << "[test_BIGNUM] SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_BIGNUM] FAILED X" << std::endl;
        }

        // Clean up
        for (auto& share : shares) {
            BN_free(share.x); // Free private share
            BN_free(share.y); // Free public key
        }

        BN_free(secret);
        BN_free(reconstructed);
    }
    catch (const std::exception& e) {
        std::cerr << "[test_BIGNUM] Error: " << e.what() << std::endl;
    }
}

void test_BIGNUM_cuda() {
    try {
        BIGNUM* mod = BN_new();
        BN_set_word(mod, 1000000007);

        // Step 1: Generate a random key
        BIGNUM* secret = generateKey_BIGNUM();
        if (showLogs) {
            std::cout << "[test_BIGNUM_cuda] Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<SHARE_BIGNUM> shares = generateShares_BIGNUM_CUDA(secret, n, t, mod);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end - start;
        if (showLogs) {
            std::cout << "[test_BIGNUM_cuda] Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }
        if (showTimes) {
            std::cout << "[test_BIGNUM_cuda] share generation time: " << duration.count() << " ms" << std::endl;
        }

        // Step 3: Reconstruct the key from the shares
        start = std::chrono::high_resolution_clock::now();
        BIGNUM* reconstructed = reconstructKey_BIGNUM_CUDA(shares, mod);
        end = std::chrono::high_resolution_clock::now();
        duration = end - start;
        if (showLogs) {
            std::cout << "[test_BIGNUM_cuda] Reconstructed Secret Key: " << reconstructed << std::endl;
        }
        if (showTimes) {
            std::cout << "[test_BIGNUM_cuda] key reconstruction time: " << duration.count() << " ms" << std::endl;
        }

        // Step 4: Verify correctness
        if (BN_cmp(secret, reconstructed) != 0) {
            std::cout << "[test_BIGNUM_cuda] SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_BIGNUM_cuda] FAILED X" << std::endl;
        }

        // Clean up
        for (auto& share : shares) {
            BN_free(share.x); // Free private share
            BN_free(share.y); // Free public key
        }

        BN_free(secret);
        BN_free(reconstructed);
    }
    catch (const std::exception& e) {
        std::cerr << "[test_BIGNUM_cuda] Error: " << e.what() << std::endl;
    }
}

int main() {
    test_int();
    std::cout << "====================================================" << std::endl;
    test_int_cuda();

    std::cout << std::endl;

    test_long();
    std::cout << "====================================================" << std::endl;
    test_long_cuda();

    std::cout << std::endl;

    test_BIGNUM();
    std::cout << "====================================================" << std::endl;
    test_BIGNUM_cuda();
    return 0;
}
