#include <iostream>
#include "tls_client.hpp"

int main() {
    TLSClient client("127.0.0.1", 5555);

    if (!client.init()) {
        std::cerr << "Failed to initialize TLS client\n";
        return 1;
    }

    if (!client.connect_server()) {
        std::cerr << "Failed to connect to server\n";
        return 1;
    }

    if (!client.send_data("Hello from TLS client!\n")) {
        std::cerr << "Failed to send data\n";
    }

    std::string response = client.receive_data();
    if (!response.empty()) {
        std::cout << "Received from server: " << response << "\n";
    } else {
        std::cout << "No response or error receiving data\n";
    }

    client.cleanup();

    return 0;
}
