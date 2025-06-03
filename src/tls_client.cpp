#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include "tls_client.hpp"
#include "compress.hpp"

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
        print_ssl_error("[TLSClient] Failed to load CA cert file (cert.pem)");
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

std::string TLSClient::read_hash_line() {
    std::string hash_line;
    char ch;
    
    while (true) {
        int bytes = SSL_read(ssl_, &ch, 1);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(ssl_, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            std::cerr << "[TLSClient] Error reading hash line\n";
            return "";
        }
        
        hash_line += ch;
        if (ch == '\n') {
            break;
        }
    }
    
    return hash_line;
}

bool TLSClient::read_exact_bytes(void* buffer, size_t bytes_to_read) {
    size_t total_read = 0;
    char* buf = static_cast<char*>(buffer);
    
    while (total_read < bytes_to_read) {
        int bytes = SSL_read(ssl_, buf + total_read, bytes_to_read - total_read);
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(ssl_, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            std::cerr << "[TLSClient] Error reading exact bytes\n";
            return false;
        }
        total_read += bytes;
    }
    
    return true;
}

std::vector<uint8_t> TLSClient::read_compressed_data() {
    uint32_t data_len;
    if (!read_exact_bytes(&data_len, sizeof(data_len))) {
        std::cerr << "[TLSClient] Failed to read data length\n";
        return {};
    }
    
    std::cout << "[TLSClient] Expecting " << data_len << " bytes of compressed data\n";
    std::vector<uint8_t> compressed_data(data_len);
    if (!read_exact_bytes(compressed_data.data(), data_len)) {
        std::cerr << "[TLSClient] Failed to read compressed data\n";
        return {};
    }
    
    return compressed_data;
}

void TLSClient::receive_and_process_packets() {
    if (!ssl_) {
        std::cerr << "[TLSClient] No SSL connection available\n";
        return;
    }
    
    std::cout << "[TLSClient] Starting to receive packet data...\n";
    
    while (true) {
        std::string hash_line = read_hash_line();
        if (hash_line.empty()) {
            std::cout << "[TLSClient] Connection closed or error reading hash line\n";
            break;
        }
        
        std::cout << "[TLSClient] Received hash: " << hash_line;
        std::vector<uint8_t> compressed_data = read_compressed_data();
        if (compressed_data.empty()) {
            std::cout << "[TLSClient] Failed to read compressed data\n";
            break;
        }
        
        std::vector<uint8_t> decompressed_data = decompress_data(
            compressed_data.data(), 
            compressed_data.size()
        );
        
        if (decompressed_data.empty()) {
            std::cerr << "[TLSClient] Failed to decompress data\n";
            continue;
        }
        
        std::string original_packet_info(
            reinterpret_cast<const char*>(decompressed_data.data()),
            decompressed_data.size()
        );
        
        std::cout << "[TLSClient] Decompressed packet info:\n" << original_packet_info << "\n";
        std::cout << "----------------------------------------\n";
    }
    
    std::cout << "[TLSClient] Packet reception ended\n";
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