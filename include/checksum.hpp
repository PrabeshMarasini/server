#ifndef CHECKSUM_HPP
#define CHECKSUM_HPP

#include <vector>
#include <string>
#include <cstdint>

std::string compute_sha256(const uint8_t* data, size_t size);

#endif