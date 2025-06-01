#ifndef TLS_CLIENT_HPP
#define TLS_CLIENT_HPP

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

class TLSClient {
public:
    TLSClient(const std::string& server_addr, int server_port);
    ~TLSClient();

    bool init();
    bool connect_server();
    bool send_data(const std::string& data);
    std::string receive_data(size_t max_len = 4096);
    void cleanup();

private:
    std::string server_address_;
    int server_port_;

    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    int socket_fd_ = -1;

    bool create_socket();
    void print_ssl_error(const std::string& prefix);
};

#endif
