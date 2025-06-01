#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

std::string compute_sha256(const uint8_t* data, size_t size) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (!mdctx) return {};

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, data, size) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return oss.str();
}
