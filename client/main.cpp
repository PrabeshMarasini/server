#include <iostream>
#include <csignal>
#include <atomic>
#include "tls_client.hpp"

std::atomic<bool> running(true);

void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received, shutting down client...\n";
    running = false;
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    TLSClient client("127.0.0.1", 5555);
    
    if (!client.init()) {
        std::cerr << "Failed to initialize TLS client\n";
        return 1;
    }
    
    if (!client.connect_server()) {
        std::cerr << "Failed to connect to server\n";
        return 1;
    }
    
    std::cout << "Successfully connected to server. Receiving packet data...\n";
    client.receive_and_process_packets();
    
    std::cout << "Cleaning up and shutting down...\n";
    client.cleanup();
    
    return 0;
}