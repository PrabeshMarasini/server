#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "client.hpp"
#include "server.hpp"
#include "crypto.hpp"
#include "packet_capture.hpp"
#include "compress.hpp"
#include "checksum.hpp"

constexpr int SERVER_PORT = 5555;
constexpr int BACKLOG = 10;
constexpr int PACKETS_PER_SEC = 5;

std::atomic<bool> running(true);

void signal_handler(int signum) {
    std::cout << "\nSignal " << signum << " received, shutting down server...\n";
    running = false;
}

void client_session(SSL* ssl) {
    std::cout << "[Session] Starting packet capture for client\n";
    
    std::thread capture_thread = start_packet_capture(PACKETS_PER_SEC, [ssl](const Packet& pkt) {
        std::ostringstream oss;
        oss << "Packet#" << pkt.number << " [" << pkt.timestamp << "] "
            << pkt.source_ip << " -> " << pkt.destination_ip
            << " [" << pkt.protocol << "] Size: " << pkt.size
            << " Data: " << pkt.hexdump << " " << pkt.other_info;
        
        std::string raw_data = oss.str();
        std::vector<uint8_t> compressed = compress_data(
            reinterpret_cast<const uint8_t*>(raw_data.data()),
            raw_data.size()
        );
        
        std::string hash = compute_sha256(compressed.data(), compressed.size());
        std::string hash_line = "SHA256: " + hash + "\n";
        
        // Check for SSL write errors
        int result = SSL_write(ssl, hash_line.c_str(), hash_line.size());
        if (result <= 0) {
            int ssl_error = SSL_get_error(ssl, result);
            std::cout << "[Session] SSL write failed with error: " << ssl_error << ", stopping capture\n";
            stop_packet_capture();
            return;
        }
        
        uint32_t len = compressed.size();
        result = SSL_write(ssl, &len, sizeof(len));
        if (result <= 0) {
            int ssl_error = SSL_get_error(ssl, result);
            std::cout << "[Session] SSL write (length) failed with error: " << ssl_error << ", stopping capture\n";
            stop_packet_capture();
            return;
        }
        
        result = SSL_write(ssl, compressed.data(), len);
        if (result <= 0) {
            int ssl_error = SSL_get_error(ssl, result);
            std::cout << "[Session] SSL write (data) failed with error: " << ssl_error << ", stopping capture\n";
            stop_packet_capture();
            return;
        }
    });
    
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
    
    std::cout << "[Session] Packet capture session ended\n";
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    initialize_openssl();
    SSL_CTX* ctx = create_server_context("cert.pem", "key.pem");
    if (!ctx) {
        std::cerr << "Failed to initialize TLS context.\n";
        return 1;
    }

    Server server(SERVER_PORT, BACKLOG);
    if (!server.start()) {
        std::cerr << "Server failed to start.\n";
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 1;
    }

    std::vector<std::thread> client_threads;

    while (running) {
        sockaddr_in client_addr{};
        int client_fd = server.accept_client(client_addr);
        if (client_fd < 0) {
            if (running) perror("accept");
            break;
        }

        std::cout << "[Main] New TLS client connection, fd: " << client_fd << "\n";

        client_threads.emplace_back([ctx, client_fd]() {
            SSL* ssl = accept_tls_connection(ctx, client_fd);
            if (!ssl) {
                std::cout << "[Main] Failed to establish TLS connection\n";
                close(client_fd);
                return;
            }

            std::cout << "[Main] TLS connection established successfully\n";
            client_session(ssl);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            std::cout << "[Main] Client session ended.\n";
        });
    }

    stop_packet_capture();

    for (auto& t : client_threads) {
        if (t.joinable()) t.join();
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    std::cout << "[Main] Server shutdown cleanly.\n";
    return 0;
}