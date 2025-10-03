# End-to-End Encrypted LAN Chat Application

## Overview

A terminal-based, end-to-end encrypted chat application for local networks. The system uses a relay server architecture where clients encrypt messages before sending and decrypt upon receiving - the server only forwards encrypted messages without ever accessing plaintext. Built with Python's socket and threading libraries, the application demonstrates core networking concepts including the client-server model, TCP sockets, message framing, and threading for concurrent connections.

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

## External Dependencies

**PyCryptodome**: Cryptographic library providing AES-EAX encryption primitives. Used specifically for the `Crypto.Cipher.AES` module to implement authenticated encryption. This is the primary external dependency for security functionality.

**Python Standard Library**: The application relies heavily on built-in modules:
- `socket`: TCP/IP networking and socket operations
- `threading`: Concurrent client handling and message reception
- `struct`: Binary data packing for message framing (length prefixes)
- `hashlib`: SHA-256 key derivation from passwords

**No Database**: The application is stateless with no persistent storage. Messages are relayed in real-time and not stored. Client lists are maintained in-memory only during server runtime.

**No External Services**: Operates entirely on the local network without internet connectivity requirements. All communication is peer-to-peer through the relay server with no cloud services or external APIs.