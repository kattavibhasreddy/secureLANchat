# End-to-End Encrypted LAN Chat Application

A simple end-to-end encrypted chat application that works over a local network using TCP sockets in Python. This project demonstrates core networking concepts (client-server model, sockets, threading, message framing) and basic cryptography (AES encryption, SHA-256 hashing for key derivation).

## Architecture

### Components

```
┌─────────────┐                  ┌─────────────┐
│   Client 1  │◄────encrypted────│   Server    │
│  (AES-EAX)  │     messages     │   (relay)   │
└─────────────┘                  └─────────────┘
                                        ▲
                                        │encrypted
                                        │messages
                                        ▼
                                 ┌─────────────┐
                                 │   Client 2  │
                                 │  (AES-EAX)  │
                                 └─────────────┘
```

### Server (`server.py`)
- Built with Python `socket` and `threading`
- Listens for client connections on port 8000
- Stores connected clients in a thread-safe list
- **Forwards encrypted messages between clients without decrypting**
- Relays ciphertext only (cannot read plaintext)
- Uses message framing with length prefixes

### Client (`client.py`)
- Built with Python `socket` + terminal-based UI
- Connects to server and provides username
- **Encrypts plaintext messages** before sending using AES
- **Decrypts received ciphertext messages** from other clients
- Shared key derived from a common password using SHA-256

### Crypto Module (`crypto.py`)
- Provides cryptographic functions:
  - `get_key(password)` → 256-bit AES key from password via SHA-256
  - `encrypt(message, key)` → returns nonce + tag + ciphertext
  - `decrypt(cipher_bytes, key)` → verifies and returns plaintext
- Uses **AES in EAX mode** (provides confidentiality + integrity)
- Authentication tag prevents message tampering

## Features

✅ **Multi-client chat** - Multiple users can connect simultaneously  
✅ **Usernames** - Each message shows who sent it  
✅ **End-to-end encryption** - Messages encrypted with AES-256  
✅ **Shared key derivation** - Password hashed via SHA-256 to create AES key  
✅ **Server is a dumb relay** - Cannot read plaintext (only forwards ciphertext)  
✅ **Message framing** - Length prefix ensures reliable transmission  
✅ **Message integrity** - EAX mode authentication prevents tampering  

## How It Works

### Encryption Flow

1. **Key Derivation**: All clients share the same password
   ```
   Password → SHA-256 → 256-bit AES Key
   ```

2. **Sending a Message**:
   ```
   Plaintext → AES-EAX Encrypt → Ciphertext → Server → Other Clients
   ```

3. **Receiving a Message**:
   ```
   Ciphertext → AES-EAX Decrypt → Plaintext (displayed)
   ```

4. **Server's Role**:
   - Receives ciphertext from sender
   - Broadcasts ciphertext to all other clients
   - **Never has access to the encryption key**
   - Cannot decrypt messages

### Message Format

Each encrypted message contains:
- **Nonce** (16 bytes): Random value for encryption
- **Tag** (16 bytes): Authentication tag for integrity
- **Ciphertext**: Encrypted message including `[username] message`

Network transmission uses framing:
- **Length Prefix** (4 bytes): Message size in big-endian format
- **Payload**: Encrypted message bytes

## Setup Instructions

### Prerequisites
- Python 3.11+
- `pycryptodome` library

### Installation

1. Install dependencies:
   ```bash
   pip install pycryptodome
   ```

### Running the Application

#### Step 1: Start the Server

In one terminal:
```bash
python server.py
```

You should see:
```
[*] Server listening on 0.0.0.0:8000
[*] Waiting for connections...
```

#### Step 2: Start Multiple Clients

In separate terminals (or on different machines on the same LAN):

**Client 1:**
```bash
python client.py
```
- Enter server IP (use `127.0.0.1` for localhost or LAN IP)
- Enter username: `Alice`
- Enter shared password: `secret123`

**Client 2:**
```bash
python client.py
```
- Enter server IP (same as Client 1)
- Enter username: `Bob`
- Enter shared password: `secret123` (must match!)

#### Step 3: Chat!

Type messages in either client. They will appear in the other client's terminal:

```
You: Hello Bob!
[Alice] Hello Bob!
```

**Important**: All clients must use the **same password** to decrypt each other's messages!

## Wireshark Demo Steps

To verify that messages are encrypted on the network:

### 1. Capture Traffic

```bash
# Start Wireshark and capture on loopback interface (lo)
sudo wireshark
```

- Select `Loopback: lo` interface
- Apply filter: `tcp.port == 8000`
- Click "Start Capture"

### 2. Send Messages

Run the server and clients as described above, then send a few messages.

### 3. Analyze Packets

In Wireshark:
1. Find a packet from client to server
2. Right-click → "Follow" → "TCP Stream"
3. You should see:
   - **Binary data** (ciphertext) - NOT readable text
   - Length prefixes (4 bytes before each message)
   - No plaintext message content visible

### What You'll Observe

✅ **Without Encryption**: You would see plaintext like `[Alice] Hello Bob!`  
✅ **With Encryption**: You only see random-looking bytes (ciphertext)

This proves the messages are encrypted in transit!

## Example Session

```
Terminal 1 (Server):
[*] Server listening on 0.0.0.0:8000
[*] Waiting for connections...
[+] New connection from ('127.0.0.1', 54321)
[+] New connection from ('127.0.0.1', 54322)
[*] Relaying encrypted message from ('127.0.0.1', 54321)
[*] Relaying encrypted message from ('127.0.0.1', 54322)

Terminal 2 (Client - Alice):
=== End-to-End Encrypted Chat Client ===

Enter your username: Alice
Enter shared password: secret123
Enter server IP (default 127.0.0.1): 
[*] Connecting to 127.0.0.1:8000...
[*] Connected! Type your messages (Ctrl+C to quit)

You: Hey everyone!
[Bob] Hi Alice, how are you?
You: Doing great!

Terminal 3 (Client - Bob):
=== End-to-End Encrypted Chat Client ===

Enter your username: Bob
Enter shared password: secret123
Enter server IP (default 127.0.0.1): 
[*] Connecting to 127.0.0.1:8000...
[*] Connected! Type your messages (Ctrl+C to quit)

[Alice] Hey everyone!
You: Hi Alice, how are you?
[Alice] Doing great!
```

## Security Considerations

### What This Provides
- ✅ **Confidentiality**: Messages encrypted with AES-256
- ✅ **Integrity**: EAX mode authentication prevents tampering
- ✅ **End-to-End**: Server cannot read messages

### Limitations
- ⚠️ **Shared Password**: All clients use the same password (not practical for real apps)
- ⚠️ **No Key Exchange**: Password must be shared out-of-band
- ⚠️ **No Forward Secrecy**: Same key used for all messages
- ⚠️ **No User Authentication**: Anyone with password can impersonate others
- ⚠️ **Replay Attacks**: Messages could theoretically be replayed
- ⚠️ **No Server Authentication**: Clients don't verify server identity

### For Production Use, Add:
- Diffie-Hellman key exchange
- Per-session keys with forward secrecy
- Digital signatures for authentication
- TLS for transport security
- Public key infrastructure (PKI)

## Technical Details

### Libraries Used
- `socket`: TCP networking
- `threading`: Concurrent client handling
- `struct`: Binary message framing
- `hashlib`: SHA-256 key derivation
- `Crypto.Cipher.AES`: AES-EAX encryption

### Why AES-EAX?
- Provides both **encryption** and **authentication**
- Single-pass operation (efficient)
- Prevents tampering and forgery
- Includes a nonce (prevents replay attacks when implemented properly)

### Message Framing
Without framing, TCP streams would not have message boundaries. We use:
```
[4 bytes: length] [N bytes: encrypted message]
```

This allows the receiver to know exactly how many bytes to read for each message.

## Troubleshooting

**Problem**: "Connection refused"  
**Solution**: Make sure the server is running first

**Problem**: "Garbled text" or decryption errors  
**Solution**: Ensure all clients use the **exact same password**

**Problem**: Messages not appearing  
**Solution**: Check that firewall allows port 8000

**Problem**: Can't connect from other machines  
**Solution**: Use the server's LAN IP (e.g., `192.168.1.100`) instead of `127.0.0.1`

## License

Educational project - free to use and modify.
