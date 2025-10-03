"""
Threaded TCP server for encrypted chat with password-based rooms.
Relays encrypted messages between clients in the same password group.
"""

import socket
import threading
import struct
import hashlib


class ChatServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        # Dictionary to store clients by password hash (room)
        self.rooms = {}  # {password_hash: [client_sockets]}
        self.rooms_lock = threading.Lock()
        
    def get_password_hash(self, password: str) -> str:
        """Get SHA-256 hash of password for room identification."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def broadcast_to_room(self, message_bytes: bytes, room_hash: str, sender_socket=None):
        """
        Broadcast encrypted message to all clients in the same room except sender.
        
        Args:
            message_bytes: Encrypted message bytes to broadcast
            room_hash: Password hash identifying the room
            sender_socket: Socket of the client who sent the message
        """
        with self.rooms_lock:
            if room_hash in self.rooms:
                for client_socket in self.rooms[room_hash]:
                    if client_socket != sender_socket:
                        try:
                            self.send_message(client_socket, message_bytes)
                        except Exception as e:
                            print(f"Error broadcasting to client in room {room_hash[:8]}...: {e}")
                        
    def send_message(self, client_socket: socket.socket, message_bytes: bytes):
        """
        Send a message with length prefix for framing.
        
        Args:
            client_socket: Socket to send message to
            message_bytes: Message bytes to send
        """
        message_length = struct.pack('>I', len(message_bytes))
        client_socket.sendall(message_length + message_bytes)
        
    def receive_message(self, client_socket: socket.socket):
        """
        Receive a message with length prefix.
        
        Args:
            client_socket: Socket to receive from
            
        Returns:
            Received message bytes or None if connection closed
        """
        raw_msglen = self.recvall(client_socket, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(client_socket, msglen)
        
    def recvall(self, client_socket: socket.socket, n: int):
        """
        Helper to receive exactly n bytes from socket.
        
        Args:
            client_socket: Socket to receive from
            n: Number of bytes to receive
            
        Returns:
            Received bytes or None if connection closed
        """
        data = bytearray()
        while len(data) < n:
            packet = client_socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
        
    def handle_client(self, client_socket: socket.socket, address):
        """
        Handle a single client connection in a separate thread.
        
        Args:
            client_socket: Client's socket connection
            address: Client's address tuple (host, port)
        """
        print(f"[+] New connection from {address}")
        
        # First message should contain the password hash for room assignment
        try:
            password_hash = self.receive_message(client_socket)
            if not password_hash:
                client_socket.close()
                return
                
            room_hash = password_hash.decode('utf-8')
            print(f"[*] Client {address} joining room {room_hash[:8]}...")
            
            # Add client to the appropriate room
            with self.rooms_lock:
                if room_hash not in self.rooms:
                    self.rooms[room_hash] = []
                self.rooms[room_hash].append(client_socket)
                room_size = len(self.rooms[room_hash])
                
            print(f"[*] Room {room_hash[:8]}... now has {room_size} client(s)")
            
            # Send confirmation
            self.send_message(client_socket, b"JOINED_ROOM")
            
            # Handle messages from this client
            while True:
                message_bytes = self.receive_message(client_socket)
                if not message_bytes:
                    break
                    
                print(f"[*] Relaying encrypted message from {address} in room {room_hash[:8]}...")
                self.broadcast_to_room(message_bytes, room_hash, client_socket)
                
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        finally:
            # Remove client from room
            with self.rooms_lock:
                for room_hash, clients in self.rooms.items():
                    if client_socket in clients:
                        clients.remove(client_socket)
                        if not clients:  # Remove empty room
                            del self.rooms[room_hash]
                        print(f"[-] Client {address} left room {room_hash[:8]}... (room now has {len(clients)} client(s))")
                        break
            client_socket.close()
            print(f"[-] Connection closed: {address}")
            
    def start(self):
        """Start the server and listen for connections."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for connections...")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            server_socket.close()


if __name__ == "__main__":
    server = ChatServer()
    server.start()
