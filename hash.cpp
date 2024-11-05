#include <openssl/evp.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>

#include "hash.h"

// Function to compute SHA-256 hash
std::string sha256(const std::string& message) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    // Create and initialize the context
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create OpenSSL EVP context");
    }

    // Initialize the hashing context with SHA-256
    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Update the hash with the message
    if (EVP_DigestUpdate(context, message.c_str(), message.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Finalize the hash and get the result
    if (EVP_DigestFinal_ex(context, hash, &hash_length) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // Clean up the context
    EVP_MD_CTX_free(context);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}