#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include "tls_client.hpp"

TLSClient::TLSClient(const std::string& server_addr, int server_port)
    : server_address_(server_addr), server_port_(server_port) {}

TLSClient::~TLSClient() {
    cleanup();
}

bool TLSClient::init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_client_method();
    if (!method) {
        std::cerr << "[TLSClient] Failed to get TLS client method.\n";
        return false;
    }

    ctx_ = SSL_CTX_new(method);
    if (!ctx_) {
        print_ssl_error("[TLSClient] Failed to create SSL_CTX");
        return false;
    }

    if (!SSL_CTX_load_verify_locations(ctx_, "cert.pem", nullptr)) {
        print_ssl_error("[TLSClient] Failed to load CA cert file (../cert.pem)");
        return false;
    }

    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);

    return true;
}

bool TLSClient::create_socket() {
    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        perror("[TLSClient] socket");
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port_);

    if (inet_pton(AF_INET, server_address_.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "[TLSClient] Invalid server IP address.\n";
        return false;
    }

    if (connect(socket_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[TLSClient] connect");
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    return true;
}

bool TLSClient::connect_server() {
    if (!create_socket()) return false;

    ssl_ = SSL_new(ctx_);
    if (!ssl_) {
        print_ssl_error("[TLSClient] SSL_new failed");
        return false;
    }

    SSL_set_fd(ssl_, socket_fd_);

    if (SSL_connect(ssl_) <= 0) {
        print_ssl_error("[TLSClient] SSL_connect failed");
        return false;
    }

    std::cout << "[TLSClient] Connected with " << SSL_get_cipher(ssl_) << " encryption\n";
    return true;
}

bool TLSClient::send_data(const std::string& data) {
    if (!ssl_) return false;

    int ret = SSL_write(ssl_, data.data(), static_cast<int>(data.size()));
    if (ret <= 0) {
        print_ssl_error("[TLSClient] SSL_write failed");
        return false;
    }

    return true;
}

std::string TLSClient::receive_data(size_t max_len) {
    if (!ssl_) return "";
    
    std::string all_data;
    char buffer[4096];
    
    while (true) {
        int bytes = SSL_read(ssl_, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(ssl_, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            break;
        }
        
        buffer[bytes] = '\0';
        all_data += std::string(buffer, bytes);
        
        uint32_t data_len;
        bytes = SSL_read(ssl_, &data_len, sizeof(data_len));
        if (bytes <= 0) {
            break;
        }
        
        std::vector<uint8_t> compressed_data(data_len);
        int total_read = 0;
        while (total_read < static_cast<int>(data_len)) {
            bytes = SSL_read(ssl_, compressed_data.data() + total_read, data_len - total_read);
            if (bytes <= 0) {
                break;
            }
            total_read += bytes;
        }
        
        if (total_read == static_cast<int>(data_len)) {
            std::cout << "[TLSClient] Received packet with " << data_len << " bytes of compressed data\n";
        }
    }
    
    return all_data;
}

void TLSClient::cleanup() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }

    if (socket_fd_ != -1) {
        close(socket_fd_);
        socket_fd_ = -1;
    }

    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

void TLSClient::print_ssl_error(const std::string& prefix) {
    std::cerr << prefix << ": " << ERR_reason_error_string(ERR_get_error()) << "\n";
}