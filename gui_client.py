"""
Tkinter GUI chat client with end-to-end encryption.
Provides a user-friendly interface for the encrypted chat application.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import struct
import hashlib
import sys
from crypto import get_key, encrypt, decrypt


class ChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure LAN Chat - End-to-End Encrypted")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Connection variables
        self.socket = None
        self.host = '127.0.0.1'
        self.port = 8000
        self.key = b''
        self.username = ''
        self.password = ''
        self.running = False
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Secure LAN Chat", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection", padding="10")
        conn_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        conn_frame.columnconfigure(1, weight=1)
        
        # Server IP
        ttk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = ttk.Entry(conn_frame, textvariable=self.host_var, width=20)
        host_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Username
        ttk.Label(conn_frame, text="Username:").grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(conn_frame, textvariable=self.username_var, width=15)
        username_entry.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        # Password
        ttk.Label(conn_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(conn_frame, textvariable=self.password_var, show="*", width=20)
        password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(10, 0))
        
        # Connect button
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect)
        self.connect_btn.grid(row=1, column=2, columnspan=2, pady=(10, 0))
        
        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar(value="Disconnected")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                foreground="red", font=('Arial', 10, 'bold'))
        status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Chat frame
        chat_frame = ttk.LabelFrame(main_frame, text="Chat Room", padding="10")
        chat_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        # Messages display
        self.messages_text = scrolledtext.ScrolledText(chat_frame, height=15, width=70, 
                                                      state=tk.DISABLED, wrap=tk.WORD)
        self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Message input frame
        input_frame = ttk.Frame(chat_frame)
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        input_frame.columnconfigure(0, weight=1)
        
        self.message_var = tk.StringVar()
        message_entry = ttk.Entry(input_frame, textvariable=self.message_var, width=50)
        message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ttk.Button(input_frame, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_btn.grid(row=0, column=1)
        
        # Disconnect button
        self.disconnect_btn = ttk.Button(main_frame, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.grid(row=4, column=0, columnspan=3, pady=(10, 0))
        
        # Add some styling
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10, 'bold'))
        
    def log_message(self, message, color="black"):
        """Add a message to the chat display."""
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.insert(tk.END, message + "\n")
        self.messages_text.config(state=tk.DISABLED)
        self.messages_text.see(tk.END)
        
    def update_status(self, status, color="black"):
        """Update the status label."""
        self.status_var.set(status)
        
    def connect(self):
        """Connect to the chat server."""
        self.host = self.host_var.get().strip() or "127.0.0.1"
        self.username = self.username_var.get().strip()
        self.password = self.password_var.get().strip()
        
        if not self.username:
            messagebox.showerror("Error", "Please enter a username")
            return
            
        if not self.password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Derive encryption key
            self.key = get_key(self.password)
            password_hash = hashlib.sha256(self.password.encode('utf-8')).hexdigest()
            
            # Send password hash to join room
            self.send_message_to_server(password_hash.encode('utf-8'))
            
            # Wait for room join confirmation
            confirmation = self.receive_message_from_server()
            if confirmation and confirmation == b"JOINED_ROOM":
                self.running = True
                self.update_status(f"Connected to {self.host} as {self.username}", "green")
                self.log_message(f"[System] Connected to chat room with password: {self.password}", "blue")
                
                # Start receiving messages in a separate thread
                receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                receive_thread.start()
                
                # Update UI state
                self.connect_btn.config(state=tk.DISABLED)
                self.disconnect_btn.config(state=tk.NORMAL)
                self.send_btn.config(state=tk.NORMAL)
                
            else:
                self.socket.close()
                messagebox.showerror("Error", "Failed to join chat room")
                
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            if self.socket:
                self.socket.close()
                
    def disconnect(self):
        """Disconnect from the chat server."""
        self.running = False
        if self.socket:
            self.socket.close()
            
        self.update_status("Disconnected", "red")
        self.log_message("[System] Disconnected from server", "blue")
        
        # Update UI state
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        
    def send_message(self):
        """Send a message to the chat room."""
        message = self.message_var.get().strip()
        if not message or not self.running:
            return
            
        try:
            formatted_message = f"[{self.username}] {message}"
            encrypted_message = encrypt(formatted_message, self.key)
            self.send_message_to_server(encrypted_message)
            
            # Clear input
            self.message_var.set("")
            
        except Exception as e:
            self.log_message(f"[Error] Failed to send message: {e}", "red")
            
    def send_message_to_server(self, message_bytes):
        """Send a message with length prefix for framing."""
        message_length = struct.pack('>I', len(message_bytes))
        self.socket.sendall(message_length + message_bytes)
        
    def receive_message_from_server(self):
        """Receive a message with length prefix."""
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(msglen)
        
    def recvall(self, n):
        """Helper to receive exactly n bytes from socket."""
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
        
    def receive_messages(self):
        """Continuously receive and decrypt messages from server."""
        while self.running:
            try:
                encrypted_message = self.receive_message_from_server()
                if not encrypted_message:
                    break
                    
                # Try to decrypt the message
                try:
                    decrypted_message = decrypt(encrypted_message, self.key)
                    self.root.after(0, lambda: self.log_message(decrypted_message))
                except Exception:
                    # Message couldn't be decrypted - likely from different password group
                    # Just ignore it
                    pass
                
            except Exception as e:
                if self.running:
                    self.root.after(0, lambda: self.log_message(f"[Error] Connection lost: {e}", "red"))
                break
                
        self.root.after(0, self.disconnect)
        
    def run(self):
        """Start the GUI application."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
        
    def on_closing(self):
        """Handle window closing."""
        if self.running:
            self.disconnect()
        self.root.destroy()


if __name__ == "__main__":
    app = ChatGUI()
    app.run()
