# MNA Remote Packet Monitor

A secure TLS-based network packet monitoring system with real-time compression and streaming capabilities.

## Prerequisites

Install the required libraries:
- **base-devel** - Build tools and compiler
- **openssl** - TLS/SSL encryption
- **zstd** - Data compression
- **libpcap** - Packet capture

```bash
sudo pacman -Syu base-devel openssl zstd libpcap
```

## Setup

### 1. Generate TLS Certificates

```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
```

### 2. Build the Applications

**Build Server:**
```bash
g++ -std=c++17 -I./include -pthread main.cpp src/*.cpp -o MNA-Remote-Server -lssl -lcrypto -lzstd
```

**Build Client:**
```bash
g++ -std=c++17 -I./include -pthread client/main.cpp src/tls_client.cpp src/compress.cpp src/crypto.cpp src/checksum.cpp -o MNA-Remote-Client -lssl -lcrypto -lzstd
```

## Usage

### 1. Start the Server
```bash
./MNA-Remote-Server
```

### 2. Connect the Client
In a new terminal:
```bash
./MNA-Remote-Client
```

## Expected Output

- **Server**: Captures network packets and streams compressed data to connected clients
- **Client**: Receives and decompresses packet data with SHA256 verification

The client will display real-time network packet information including source/destination IPs, protocols, and packet data.

## Features

- ✅ Secure TLS encryption
- ✅ Real-time packet capture
- ✅ Data compression with zstd
- ✅ SHA256 integrity verification
- ✅ Multi-client support