#ifndef COMPRESS_HPP
#define COMPRESS_HPP

#include <vector>
#include <cstdint>

std::vector<uint8_t> compress_data(const uint8_t* input, size_t input_size);
std::vector<uint8_t> decompress_data(const uint8_t* compressed, size_t compressed_size);

#endif