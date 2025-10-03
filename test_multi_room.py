"""
Test script to verify multiple independent chat rooms work correctly.
"""

import socket
import threading
import struct
import hashlib
import time
from crypto import get_key, encrypt, decrypt


def test_client(host, port, username, password, room_name):
    """Test client that sends a few messages and receives responses."""
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        # Get encryption key
        key = get_key(password)
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        # Send password hash to join room
        send_message(sock, password_hash.encode('utf-8'))
        
        # Wait for confirmation
        confirmation = receive_message(sock)
        if confirmation != b"JOINED_ROOM":
            print(f"[{room_name}] Failed to join room")
            return
            
        print(f"[{room_name}] {username} joined room with password: {password}")
        
        # Send a test message
        test_message = f"[{username}] Hello from {room_name}!"
        encrypted_message = encrypt(test_message, key)
        send_message(sock, encrypted_message)
        
        # Wait a bit for other messages
        time.sleep(2)
        
        # Try to receive messages
        try:
            while True:
                encrypted_msg = receive_message(sock)
                if not encrypted_msg:
                    break
                    
                try:
                    decrypted_msg = decrypt(encrypted_msg, key)
                    print(f"[{room_name}] {username} received: {decrypted_msg}")
                except Exception:
                    print(f"[{room_name}] {username} received message from different room (ignored)")
                    
        except Exception as e:
            print(f"[{room_name}] {username} error receiving: {e}")
            
        sock.close()
        print(f"[{room_name}] {username} disconnected")
        
    except Exception as e:
        print(f"[{room_name}] {username} connection error: {e}")


def send_message(sock, message_bytes):
    """Send a message with length prefix for framing."""
    message_length = struct.pack('>I', len(message_bytes))
    sock.sendall(message_length + message_bytes)


def receive_message(sock):
    """Receive a message with length prefix."""
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)


def recvall(sock, n):
    """Helper to receive exactly n bytes from socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


if __name__ == "__main__":
    print("Testing multiple independent chat rooms...")
    print("Make sure the server is running first!")
    
    # Test different rooms with different passwords
    rooms = [
        ("Room A", "password1", ["Alice", "Bob"]),
        ("Room B", "password2", ["Charlie", "David"]),
        ("Room C", "password3", ["Eve", "Frank"])
    ]
    
    threads = []
    
    # Start clients for each room
    for room_name, password, users in rooms:
        for username in users:
            thread = threading.Thread(
                target=test_client,
                args=("127.0.0.1", 8000, username, password, room_name)
            )
            thread.start()
            threads.append(thread)
            time.sleep(0.5)  # Small delay between connections
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("Test completed!")
