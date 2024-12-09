#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include "common.h"
#include "gen_key.h"
#include "gen_shares.h"
#include "gen_shares_cuda.h"
#include "recon_key.h"
#include "recon_key_cuda.h"

bool showLogs = false;

void test_int() {
    try {
        // Step 1: Generate a random key
        int secret = generateKey_int(1, 100);
        if (showLogs) {
            std::cout << "Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        int n = 400;
        int t = 200;
        int mod = 101;
        auto shares = generateShares_int(secret, n, t, mod);
        if (showLogs) {
            std::cout << "Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }

        // Step 3: Reconstruct the key from the shares
        std::vector<SHARE_INT> selectedShares(shares.begin(), shares.begin() + t);
        int reconstructed = reconstructKey_int(selectedShares, mod);
        if (showLogs) {
            std::cout << "Reconstructed Secret Key: " << reconstructed << std::endl;
        }

        // Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_int]            SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_int]            FAILED X" << std::endl;
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
            std::cout << "Original Secret Key: " << secret << std::endl;
        }

        // Step 2: Split the key into shares
        int n = 100, t = 50, mod = 101;
        auto shares = generateShares_int_CUDA(secret, n, t, mod);
        if (showLogs) {
            std::cout << "Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }

        // Reconstruct the secret using CUDA
        int reconstructed = reconstructKey_int_CUDA(shares, mod);
        if (showLogs) {
            std::cout << "Reconstructed Secret Key: " << reconstructed << std::endl;
        }

        // Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_int_cuda]       SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_int_cuda]       FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void test_long() {
    try {
        unsigned long long order = 1000000007;
        unsigned long long secret = generateKey_long(order);
        if (showLogs) {
            std::cout << "Original Secret Key: " << secret << std::endl;
        }

        int n = 5, t = 3;
        std::vector<SHARE_LONG> shares = generateShares_long(secret, n, t, order);
        if (showLogs) {
            std::cout << "Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }

        unsigned long long reconstructed = reconstructKey_long(shares, order);
        if (showLogs) {
            std::cout << "Reconstructed Secret Key: " << reconstructed << std::endl;
        }

        // Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_long]           SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_long]           FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void test_long_cuda() {
    try {
        unsigned long long order = 1000000007;
        unsigned long long secret = generateKey_long(order);
        if (showLogs) {
            std::cout << "Original Secret Key: " << secret << std::endl;
        }

        int n = 5, t = 3;
        std::vector<SHARE_LONG> shares = generateShares_long_CUDA(secret, n, t, order);
        if (showLogs) {
            std::cout << "Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }

        unsigned long long reconstructed = reconstructKey_long_CUDA(shares, order);
        if (showLogs) {
            std::cout << "Reconstructed Secret Key: " << reconstructed << std::endl;
        }

        // Verify correctness
        if (reconstructed == secret) {
            std::cout << "[test_long_cuda]      SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_long_cuda]      FAILED X" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void test_BIGNUM() {
    try {
        // Generate key pair
        BIGNUM* secret = generateKey_BIGNUM();
        if (showLogs) {
            std::cout << "Original Secret Key: " << secret << std::endl;
        }

        // Generate 100 shares with a threshold of 50
        int n = 100, t = 50;
        std::vector<SHARE_BIGNUM> shares = generateShares_BIGNUM(secret, n, t);
        if (showLogs) {
            std::cout << "Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }

        // Reconstruct the original key pair from shares
        BIGNUM* reconstructed = reconstructKey_BIGNUM(shares);
        if (showLogs) {
            std::cout << "Reconstructed Secret Key: " << reconstructed << std::endl;
        }

        if (BN_cmp(secret, reconstructed) != 0) {
            std::cout << "[test_BIGNUM]         SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_BIGNUM]         FAILED X" << std::endl;
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
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void test_BIGNUM_cuda() {
    try {
        BIGNUM* mod = BN_new();
        BN_set_word(mod, 1000000007);

        // Generate key pair
        BIGNUM* secret = generateKey_BIGNUM();
        if (showLogs) {
            std::cout << "Original Secret Key: " << secret << std::endl;
        }

        // Generate 100 shares with a threshold of 50
        int n = 100, t = 50;
        std::vector<SHARE_BIGNUM> shares = generateShares_BIGNUM_CUDA(secret, n, t, mod);
        if (showLogs) {
            std::cout << "Generated Shares:" << std::endl;
            for (const auto& share : shares) {
                std::cout << "x: " << share.x << ", y: " << share.y << std::endl;
            }
        }

        // Reconstruct the original key pair from shares
        BIGNUM* reconstructed = reconstructKey_BIGNUM_CUDA(shares, mod);
        if (showLogs) {
            std::cout << "Reconstructed Secret Key: " << reconstructed << std::endl;
        }

        if (BN_cmp(secret, reconstructed) != 0) {
            std::cout << "[test_BIGNUM_cuda]    SUCCEESS V" << std::endl;
        }
        else {
            std::cout << "[test_BIGNUM_cuda]    FAILED X" << std::endl;
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
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    test_int();
    test_int_cuda();
    test_long();
    test_long_cuda();
    test_BIGNUM();
    test_BIGNUM_cuda();
    return 0;
}
