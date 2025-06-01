#include "server.hpp"
#include <iostream>
#include <unistd.h>       
#include <cstring>        
#include <sys/socket.h>   

Server::Server(int port, int backlog) 
    : port(port), backlog(backlog), server_fd(-1) {}

Server::~Server() {
    if (server_fd >= 0) {
        close(server_fd);
        std::cout << "[Server] Socket closed.\n";
    }
}

bool Server::start() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[Server] socket");
        return false;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[Server] setsockopt");
        close(server_fd);
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[Server] bind");
        close(server_fd);
        return false;
    }

    if (listen(server_fd, backlog) < 0) {
        perror("[Server] listen");
        close(server_fd);
        return false;
    }

    std::cout << "[Server] Listening on port " << port << "\n";
    return true;
}

int Server::accept_client(sockaddr_in& client_addr) {
    socklen_t len = sizeof(client_addr);
    return accept(server_fd, (sockaddr*)&client_addr, &len);
}

int Server::get_socket_fd() const {
    return server_fd;
}
