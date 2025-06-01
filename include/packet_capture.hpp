#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP
#include <vector>
#include <string>
#include <cstdint>
#include <chrono>

struct Packet {
    uint64_t number;
    std::string timestamp;
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
    size_t size;
    std::string hexdump;
    std::string other_info;
};

void start_packet_capture(int packets_per_sec, void(*on_packet)(const Packet&));

#endif

