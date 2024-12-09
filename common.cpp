#include "common.h"

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    for (unsigned char byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::string bignumToHex(const BIGNUM* bn) {
    if (!bn) {
        throw std::runtime_error("Invalid BIGNUM");
    }
    char* hex = BN_bn2hex(bn);
    if (!hex) {
        throw std::runtime_error("Failed to convert BIGNUM to hex");
    }
    std::string hexStr(hex);
    OPENSSL_free(hex);
    return hexStr;
}

std::string bufferToHex(const unsigned char* buffer, size_t len) {
    std::string hex;
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", buffer[i]);
        hex.append(buf);
    }
    return hex;
}

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