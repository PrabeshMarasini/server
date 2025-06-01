#include <iostream>
#include <unistd.h>     
#include <cstring>
#include <sys/socket.h>
#include "client.hpp"    

constexpr int BUFFER_SIZE = 1024;

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    const char* welcome = "Welcome to MNA Remote Server.\n";
    send(client_fd, welcome, strlen(welcome), 0);

    ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::cout << "[Client] " << buffer << "\n";

        const char* reply = "ACK: Message received.\n";
        send(client_fd, reply, strlen(reply), 0);
    } else {
        std::cout << "[Client] No data received or connection closed.\n";
    }
}
