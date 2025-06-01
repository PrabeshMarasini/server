#ifndef SERVER_HPP
#define SERVER_HPP

#include <netinet/in.h>

class Server {
public:
    Server(int port, int backlog = 10);
    ~Server();

    bool start();
    int accept_client(sockaddr_in& client_addr);
    int get_socket_fd() const;

private:
    int server_fd;
    int port;
    int backlog;
};

#endif
