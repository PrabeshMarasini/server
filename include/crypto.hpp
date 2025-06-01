#ifndef CRYPTO_HPP
#define CRYPTO_HPP
#include <openssl/ssl.h>
#include <openssl/err.h>

void initialize_openssl();
void cleanup_openssl();
SSL_CTX* create_server_context(const char* cert_file, const char* key_file);
SSL* accept_tls_connection(SSL_CTX* ctx, int client_fd);

#endif