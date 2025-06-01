#include <zstd.h>
#include <iostream>
#include "compress.hpp"

std::vector<uint8_t> compress_data(const uint8_t* input, size_t input_size) {
    size_t bound = ZSTD_compressBound(input_size);
    std::vector<uint8_t> compressed(bound);

    size_t compressed_size = ZSTD_compress(compressed.data(), bound, input, input_size, 1);
    if (ZSTD_isError(compressed_size)) {
        std::cerr << "[Compression] Error: " << ZSTD_getErrorName(compressed_size) << "\n";
        return {};
    }

    compressed.resize(compressed_size);
    return compressed;
}

std::vector<uint8_t> decompress_data(const uint8_t* compressed, size_t compressed_size) {
    unsigned long long const decompressed_size = ZSTD_getFrameContentSize(compressed, compressed_size);
    if (decompressed_size == ZSTD_CONTENTSIZE_ERROR || decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        std::cerr << "[Decompression] Error: Unknown content size.\n";
        return {};
    }

    std::vector<uint8_t> decompressed(decompressed_size);
    size_t const result = ZSTD_decompress(decompressed.data(), decompressed_size, compressed, compressed_size);
    if (ZSTD_isError(result)) {
        std::cerr << "[Decompression] Error: " << ZSTD_getErrorName(result) << "\n";
        return {};
    }

    return decompressed;
}
