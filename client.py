"""
Terminal-based chat client with end-to-end encryption.
Encrypts outgoing messages and decrypts incoming messages.
"""

import socket
import threading
import struct
import sys
from crypto import get_key, encrypt, decrypt


class ChatClient:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key = b''
        self.username = None
        self.running = False
        
    def send_message(self, message_bytes: bytes):
        """
        Send a message with length prefix for framing.
        
        Args:
            message_bytes: Message bytes to send
        """
        message_length = struct.pack('>I', len(message_bytes))
        self.socket.sendall(message_length + message_bytes)
        
    def receive_message(self):
        """
        Receive a message with length prefix.
        
        Returns:
            Received message bytes or None if connection closed
        """
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(msglen)
        
    def recvall(self, n: int):
        """
        Helper to receive exactly n bytes from socket.
        
        Args:
            n: Number of bytes to receive
            
        Returns:
            Received bytes or None if connection closed
        """
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
        
    def receive_messages(self):
        """
        Continuously receive and decrypt messages from server.
        Runs in a separate thread.
        """
        while self.running:
            try:
                encrypted_message = self.receive_message()
                if not encrypted_message:
                    break
                    
                decrypted_message = decrypt(encrypted_message, self.key)
                print(f"\n{decrypted_message}")
                print(f"You: ", end='', flush=True)
                
            except Exception as e:
                if self.running:
                    print(f"\n[!] Error receiving message: {e}")
                break
                
        print("\n[*] Disconnected from server")
        self.running = False
        
    def send_messages(self):
        """
        Continuously read user input, encrypt, and send messages.
        """
        print("\n[*] Connected! Type your messages (Ctrl+C to quit)\n")
        
        while self.running:
            try:
                message = input("You: ")
                if message.strip():
                    formatted_message = f"[{self.username}] {message}"
                    encrypted_message = encrypt(formatted_message, self.key)
                    self.send_message(encrypted_message)
                    
            except KeyboardInterrupt:
                print("\n[*] Disconnecting...")
                self.running = False
                break
            except Exception as e:
                print(f"[!] Error sending message: {e}")
                self.running = False
                break
                
    def start(self):
        """Connect to server and start chat session."""
        print("=== End-to-End Encrypted Chat Client ===\n")
        
        self.username = input("Enter your username: ").strip()
        if not self.username:
            self.username = "Anonymous"
            
        password = input("Enter shared password: ").strip()
        if not password:
            print("[!] Password cannot be empty")
            return
            
        self.key = get_key(password)
        
        try:
            self.socket.connect((self.host, self.port))
            print(f"[*] Connecting to {self.host}:{self.port}...")
            
            self.running = True
            
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.send_messages()
            
        except Exception as e:
            print(f"[!] Connection error: {e}")
        finally:
            if self.socket:
                self.socket.close()


if __name__ == "__main__":
    host = input("Enter server IP (default 127.0.0.1): ").strip() or "127.0.0.1"
    client = ChatClient(host=host)
    client.start()
