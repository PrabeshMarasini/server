#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    std::ifstream infile("file_to_send", std::ios::binary);
    while (!infile.eof()) {
        infile.read(buffer, BUFFER_SIZE);
        send(sock, buffer, infile.gcount(), 0);
    }

    std::cout << "File sent.\n";
    infile.close();
    close(sock);
    return 0;
}
