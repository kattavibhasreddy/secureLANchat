"""
Threaded TCP server for encrypted chat.
Relays encrypted messages between clients without decrypting them.
"""

import socket
import threading
import struct


class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.clients = []
        self.clients_lock = threading.Lock()
        
    def broadcast(self, message_bytes: bytes, sender_socket=None):
        """
        Broadcast encrypted message to all clients except sender.
        
        Args:
            message_bytes: Encrypted message bytes to broadcast
            sender_socket: Socket of the client who sent the message
        """
        with self.clients_lock:
            for client_socket in self.clients:
                if client_socket != sender_socket:
                    try:
                        self.send_message(client_socket, message_bytes)
                    except Exception as e:
                        print(f"Error broadcasting to client: {e}")
                        
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
        
        with self.clients_lock:
            self.clients.append(client_socket)
            
        try:
            while True:
                message_bytes = self.receive_message(client_socket)
                if not message_bytes:
                    break
                    
                print(f"[*] Relaying encrypted message from {address}")
                self.broadcast(message_bytes, client_socket)
                
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        finally:
            with self.clients_lock:
                self.clients.remove(client_socket)
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
