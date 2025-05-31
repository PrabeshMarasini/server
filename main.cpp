#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <csignal>
#include <cstring>
#include <unistd.h>     
#include <netinet/in.h>  
#include <sys/socket.h>  
#include "client_handler.hpp"  

constexpr int SERVER_PORT = 5555;
constexpr int BACKLOG = 10;

std::atomic<bool> running(true);

void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received, shutting down server...\n";
    running = false;
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    std::cout << "Server listening on port " << SERVER_PORT << "\n";

    std::vector<std::thread> client_threads;

    while (running) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running) {
                perror("accept");
            }
            break;
        }

        std::cout << "New client connected, fd: " << client_fd << "\n";

        client_threads.emplace_back([client_fd]() {
            handle_client(client_fd);
            close(client_fd);
            std::cout << "Client disconnected, fd: " << client_fd << "\n";
        });
    }

    for (auto& t : client_threads) {
        if (t.joinable()) t.join();
    }

    close(server_fd);
    std::cout << "Server shutdown cleanly.\n";

    return 0;
}
