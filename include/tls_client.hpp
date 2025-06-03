#ifndef TLS_CLIENT_HPP
#define TLS_CLIENT_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/err.h>

class TLSClient {
public:
    TLSClient(const std::string& server_addr, int server_port);
    ~TLSClient();

    bool init();
    bool connect_server();
    void receive_and_process_packets();
    void cleanup();

private:
    std::string server_address_;
    int server_port_;

    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    int socket_fd_ = -1;

    bool create_socket();
    void print_ssl_error(const std::string& prefix);
    
    std::string read_hash_line();
    bool read_exact_bytes(void* buffer, size_t bytes_to_read);
    std::vector<uint8_t> read_compressed_data();
};

#endif