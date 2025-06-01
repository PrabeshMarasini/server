#include <thread>
#include <sstream>
#include <iomanip>
#include <random>
#include <iostream>
#include <atomic>
#include "packet_capture.hpp"

static std::atomic<bool> capturing(true);

std::string get_current_time_string() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%F %T")
        << "." << std::setw(3) << std::setfill('0') << millis.count();
    return oss.str();
}

std::string random_ip() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(1, 254);
    std::ostringstream oss;
    oss << dist(gen) << "." << dist(gen) << "." << dist(gen) << "." << dist(gen);
    return oss.str();
}

std::string generate_hexdump(size_t len = 64) {
    std::ostringstream oss;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) oss << "\n";
        oss << std::hex << std::setw(2) << std::setfill('0') << dist(gen) << " ";
    }
    return oss.str();
}

std::string random_string(size_t length = 10) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    std::string str;
    for (size_t i = 0; i < length; ++i) {
        str += charset[dist(gen)];
    }
    return str;
}

std::thread start_packet_capture(int packets_per_sec, std::function<void(const Packet&)> on_packet) {
    capturing = true;
    
    return std::thread([=]() {
        uint64_t counter = 0;
        int interval_us = 1'000'000 / packets_per_sec;
        std::vector<std::string> protocols = {"TCP", "UDP", "ICMP"};
        
        std::cout << "[PacketCapture] Thread started\n";
        
        while (capturing) {
            Packet pkt;
            pkt.number = ++counter;
            pkt.timestamp = get_current_time_string();
            pkt.source_ip = random_ip();
            pkt.destination_ip = random_ip();
            pkt.protocol = protocols[counter % protocols.size()];
            pkt.size = 64 + (counter % 256);
            pkt.hexdump = generate_hexdump(32);
            pkt.other_info = "info:" + random_string(6);
            
            on_packet(pkt);
            std::this_thread::sleep_for(std::chrono::microseconds(interval_us));
        }
        
        std::cout << "[PacketCapture] Thread ending\n";
    });
}

void stop_packet_capture() {
    capturing = false;
}