"""
WebSocket server for web-based encrypted chat client.
Serves HTML frontend and relays encrypted messages via WebSocket.
"""

import asyncio
import websockets
import json
from pathlib import Path
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import threading


class ChatWebSocketServer:
    def __init__(self, host='0.0.0.0', ws_port=8001, http_port=5000):
        self.host = host
        self.ws_port = ws_port
        self.http_port = http_port
        self.clients = set()
        
    async def handle_client(self, websocket):
        """
        Handle a WebSocket client connection.
        
        Args:
            websocket: WebSocket connection
        """
        self.clients.add(websocket)
        client_addr = websocket.remote_address
        print(f"[+] Web client connected from {client_addr}")
        
        try:
            async for message in websocket:
                data = json.loads(message)
                
                if data['type'] == 'message':
                    encrypted_msg = data['encrypted']
                    print(f"[*] Relaying encrypted message from web client {client_addr}")
                    
                    await self.broadcast(json.dumps({
                        'type': 'message',
                        'encrypted': encrypted_msg
                    }), websocket)
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[!] Error handling web client {client_addr}: {e}")
        finally:
            self.clients.remove(websocket)
            print(f"[-] Web client disconnected: {client_addr}")
            
    async def broadcast(self, message, sender_socket=None):
        """
        Broadcast message to all clients except sender.
        
        Args:
            message: JSON message to broadcast
            sender_socket: WebSocket of the sender
        """
        if self.clients:
            tasks = [
                client.send(message)
                for client in self.clients
                if client != sender_socket
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                
    async def start_websocket_server(self):
        """Start WebSocket server for chat."""
        async with websockets.serve(self.handle_client, self.host, self.ws_port):
            print(f"[*] WebSocket server listening on {self.host}:{self.ws_port}")
            await asyncio.Future()
            
    def start_http_server(self):
        """Start HTTP server to serve static files."""
        handler = SimpleHTTPRequestHandler
        with TCPServer((self.host, self.http_port), handler) as httpd:
            print(f"[*] HTTP server listening on {self.host}:{self.http_port}")
            httpd.serve_forever()
            
    def start(self):
        """Start both HTTP and WebSocket servers."""
        print("[*] Starting web chat server...")
        
        http_thread = threading.Thread(target=self.start_http_server, daemon=True)
        http_thread.start()
        
        asyncio.run(self.start_websocket_server())


if __name__ == "__main__":
    server = ChatWebSocketServer()
    server.start()
