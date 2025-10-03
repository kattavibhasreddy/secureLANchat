# End-to-End Encrypted LAN Chat Application

## Overview

An end-to-end encrypted chat application for local networks with both terminal-based and web-based clients. The system uses a relay server architecture where clients encrypt messages before sending and decrypt upon receiving - the server only forwards encrypted messages without ever accessing plaintext. Built with Python's socket and threading libraries, the application demonstrates core networking concepts including the client-server model, TCP sockets, message framing, and threading for concurrent connections.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Communication Architecture

**Client-Server Relay Model**: The application uses a centralized relay server that forwards encrypted messages between clients without decrypting them. This ensures end-to-end encryption where only the sender and recipients can read message content.

**Protocol Design**: Custom message framing protocol using length prefixes (4-byte big-endian integers) to handle variable-length messages over TCP streams. This prevents message boundary issues and allows reliable transmission of arbitrary-length encrypted payloads.

**Concurrency Model**: Threading-based architecture where the server spawns a new thread for each connected client. Thread-safe operations are ensured using locks when accessing the shared clients list. Clients also use separate threads for sending and receiving messages to enable full-duplex communication.

### Encryption Architecture

**Symmetric Encryption**: Uses AES-256 in EAX mode for authenticated encryption. EAX mode provides both confidentiality (encryption) and integrity (authentication tag), preventing tampering attacks.

**Key Derivation**: Shared encryption keys are derived from a common password using SHA-256 hashing. All clients must use the same password to communicate, as the key derivation is deterministic.

**Message Format**: Encrypted messages are packaged as: `nonce || authentication_tag || ciphertext`. The nonce ensures unique encryption even for identical messages, while the authentication tag enables integrity verification during decryption.

**Security Model**: End-to-end encryption is achieved by encrypting messages client-side before transmission. The server operates on ciphertext only and cannot access plaintext, ensuring privacy even if the server is compromised.

### Network Architecture

**Transport Layer**: TCP sockets provide reliable, ordered, connection-oriented communication between clients and server. Uses IPv4 addressing (AF_INET).

**Server Binding**: Server listens on all interfaces (0.0.0.0) at port 8000, allowing connections from any device on the local network.

**Client Connections**: Clients connect to server using IP address and port, defaulting to localhost (127.0.0.1:8000) for testing but configurable for LAN operation.

**Message Broadcasting**: Server maintains a list of connected client sockets and broadcasts incoming encrypted messages to all clients except the sender, enabling group chat functionality.

## Recent Changes

**October 3, 2025**: Added web-based frontend with browser interface. The application now supports both terminal clients (using TCP sockets) and web clients (using WebSockets). Web clients use Web Crypto API for client-side encryption with AES-GCM instead of AES-EAX, maintaining the same end-to-end encryption security model.

## External Dependencies

**PyCryptodome**: Cryptographic library providing AES-EAX encryption primitives for terminal clients. Used specifically for the `Crypto.Cipher.AES` module to implement authenticated encryption.

**WebSockets**: Python library for WebSocket protocol support, enabling real-time bidirectional communication with web browsers.

**Python Standard Library**: The application relies heavily on built-in modules:
- `socket`: TCP/IP networking and socket operations
- `threading`: Concurrent client handling and message reception
- `struct`: Binary data packing for message framing (length prefixes)
- `hashlib`: SHA-256 key derivation from passwords
- `http.server`: Serving static HTML/CSS/JS files for web frontend
- `asyncio`: Asynchronous WebSocket server implementation

**Web Crypto API**: Built-in browser cryptography API for client-side encryption in the web frontend. Provides SHA-256 hashing and AES-GCM encryption without requiring external libraries.

**No Database**: The application is stateless with no persistent storage. Messages are relayed in real-time and not stored. Client lists are maintained in-memory only during server runtime.

**No External Services**: Operates entirely on the local network without internet connectivity requirements. All communication is peer-to-peer through the relay server with no cloud services or external APIs.