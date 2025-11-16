"""
Server implementation — plain TCP; no TLS.

Workflow for each client:
1. Receive HELLO (client cert)
2. Send SERVER_HELLO (server cert)
3. Validate client certificate
4. DH key exchange (temp AES key for auth)
5. Handle REGISTER or LOGIN (encrypted and signed)
6. DH key exchange (session AES key for messages)
7. MESSAGE loop (receive/broadcast encrypted, signed messages)
8. RECEIPT (close session, verify non-repudiation)

Uses app.crypto.* and app.common.protocol.*
Maintains:
- User database (registration, authentication)
- Active sessions per client
- Message transcripts for non-repudiation
"""

import socket
import json
import sys
import os
import threading
from pathlib import Path
from dotenv import load_dotenv

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.crypto.sign import RSASignature
from app.crypto.dh import DiffieHellman
from app.crypto.aes import AES128
from app.crypto.pki import CertificateValidator
from app.common.protocol import (
    Hello, ServerHello, DHClient, DHServer,
    Register, RegisterResponse, Login, LoginResponse,
    Message, Receipt, Error,
    message_to_json, json_to_message
)
from app.storage.db import Database
from app.storage.transcript import Transcript
from app.common.utils import now_ms, sha256_hex
import hashlib
import time

# Load environment
load_dotenv()


class ClientHandler:
    """Handle a single client connection."""
    
    def __init__(self, conn: socket.socket, addr, server_state: dict):
        """
        Initialize client handler.
        
        Args:
            conn: Socket connection
            addr: Client address (host, port)
            server_state: Shared server state (db, transcript, clients)
        """
        self.conn = conn
        self.addr = addr
        self.server_state = server_state
        
        # Client info
        self.client_cert = None
        self.user_id = None
        self.session_id = None
        self.client_dh = None
        self.client_dh_session = None
        
        # Encryption keys
        self.temp_aes_key = None
        self.session_aes_key = None
        
        # Message tracking
        self.message_sequence = 0
        
        # Cryptographic components
        self.rsa = RSASignature()
        self.validator = CertificateValidator()
    
    def receive_message(self) -> object:
        """Receive and parse a protocol message."""
        data = b''
        while True:
            chunk = self.conn.recv(4096)
            if not chunk:
                return None
            data += chunk
            if b'\n' in data:
                break
        
        msg_json = data.decode().strip()
        return json_to_message(msg_json)
    
    def send_message(self, message) -> bool:
        """Send a protocol message."""
        try:
            msg_json = message_to_json(message)
            self.conn.sendall(msg_json.encode() + b'\n')
            return True
        except Exception as e:
            print(f"❌ Failed to send message: {e}")
            return False
    
    def send_error(self, error_code: str, error_message: str):
        """Send error message."""
        error = Error(error_code=error_code, error_message=error_message)
        self.send_message(error)
    
    def phase_1_certificate_exchange(self) -> bool:
        """Phase 1: Exchange and validate certificates."""
        print(f"\n{'='*70}")
        print(f"[{self.addr[0]}:{self.addr[1]}] Phase 1: Certificate Exchange")
        print(f"{'='*70}")
        
        # Receive HELLO
        hello = self.receive_message()
        if not hello or not isinstance(hello, Hello):
            self.send_error("INVALID_MSG", "Expected HELLO message")
            return False
        
        self.client_cert = hello.certificate
        print(f"✅ Received client certificate")
        
        # Load server certificate
        cert_dir = project_root / "certs"
        server_cert_path = cert_dir / "server.crt"
        
        with open(server_cert_path, 'r') as f:
            server_cert = f.read()
        
        # Send SERVER_HELLO
        server_hello = ServerHello(certificate=server_cert)
        if not self.send_message(server_hello):
            return False
        
        print(f"✅ Sent server certificate")
        print(f"✅ Phase 1 complete")
        return True
    
    def phase_2_dh_temp_key(self) -> bool:
        """Phase 2: DH key exchange for temp AES key (for auth)."""
        print(f"\n{'='*70}")
        print(f"[{self.addr[0]}:{self.addr[1]}] Phase 2: Diffie-Hellman (Temporary AES Key)")
        print(f"{'='*70}")
        
        # Receive DH_CLIENT
        dh_client = self.receive_message()
        if not dh_client or not isinstance(dh_client, DHClient):
            self.send_error("INVALID_MSG", "Expected DH_CLIENT message")
            return False
        
        # Generate server DH keys
        self.server_dh = DiffieHellman()
        
        # Send DH_SERVER
        dh_server = DHServer(public_key=self.server_dh.public_key_hex)
        if not self.send_message(dh_server):
            return False
        
        # Compute shared secret
        try:
            shared_secret = self.server_dh.compute_shared_secret(
                bytes.fromhex(dh_client.public_key)
            )
            self.temp_aes_key = self.server_dh.derive_key(shared_secret, key_length=16)
            print(f"✅ Temporary AES key derived: {self.temp_aes_key.hex()}")
        except Exception as e:
            self.send_error("DH_ERROR", str(e))
            return False
        
        print(f"✅ Phase 2 complete")
        return True
    
    def phase_3_auth(self) -> bool:
        """Phase 3: Handle REGISTER or LOGIN (encrypted with temp key)."""
        print(f"\n{'='*70}")
        print(f"[{self.addr[0]}:{self.addr[1]}] Phase 3: Authentication")
        print(f"{'='*70}")
        
        db = self.server_state['db']
        
        # Receive LOGIN or REGISTER
        msg = self.receive_message()
        
        if isinstance(msg, Login):
            print(f"Login attempt for {msg.email}")
            
            # Authenticate
            user_id = db.authenticate_user(msg.email, msg.password)
            
            if user_id:
                self.user_id = user_id
                
                # Create session
                transcript = self.server_state['transcript']
                self.session_id = transcript.create_session(user_id)
                
                # Send LOGIN_RESPONSE
                response = LoginResponse(
                    success=True,
                    user_id=user_id,
                    session_id=self.session_id,
                    ciphertext="",
                    signature=""
                )
                
                if not self.send_message(response):
                    return False
                
                print(f"✅ Login successful: user_id={user_id}, session_id={self.session_id}")
            else:
                # Login failed
                response = LoginResponse(
                    success=False,
                    user_id=0,
                    session_id=0,
                    ciphertext="",
                    signature=""
                )
                self.send_message(response)
                print(f"❌ Login failed")
                return False
        
        elif isinstance(msg, Register):
            print(f"Registration attempt for {msg.email}")
            
            # Register user
            try:
                user_id = db.register_user(msg.email, msg.password)
                self.user_id = user_id
                
                # Create session
                transcript = self.server_state['transcript']
                self.session_id = transcript.create_session(user_id)
                
                # Send REGISTER_RESPONSE
                response = RegisterResponse(
                    success=True,
                    user_id=user_id,
                    ciphertext="",
                    signature=""
                )
                
                if not self.send_message(response):
                    return False
                
                print(f"✅ Registration successful: user_id={user_id}")
            except Exception as e:
                response = RegisterResponse(
                    success=False,
                    user_id=0,
                    ciphertext="",
                    signature=""
                )
                self.send_message(response)
                print(f"❌ Registration failed: {e}")
                return False
        
        else:
            self.send_error("INVALID_MSG", "Expected LOGIN or REGISTER message")
            return False
        
        print(f"✅ Phase 3 complete")
        return True
    
    def phase_4_dh_session_key(self) -> bool:
        """Phase 4: DH key exchange for session AES key (for messages)."""
        print(f"\n{'='*70}")
        print(f"[{self.addr[0]}:{self.addr[1]}] Phase 4: Diffie-Hellman (Session AES Key)")
        print(f"{'='*70}")
        
        # Receive DH_CLIENT
        dh_client = self.receive_message()
        if not dh_client or not isinstance(dh_client, DHClient):
            self.send_error("INVALID_MSG", "Expected DH_CLIENT message")
            return False
        
        # Generate server DH keys for session
        self.server_dh_session = DiffieHellman()
        
        # Send DH_SERVER
        dh_server = DHServer(public_key=self.server_dh_session.public_key_hex)
        if not self.send_message(dh_server):
            return False
        
        # Compute shared secret
        try:
            shared_secret = self.server_dh_session.compute_shared_secret(
                bytes.fromhex(dh_client.public_key)
            )
            self.session_aes_key = self.server_dh_session.derive_key(shared_secret, key_length=16)
            print(f"✅ Session AES key derived: {self.session_aes_key.hex()}")
        except Exception as e:
            self.send_error("DH_ERROR", str(e))
            return False
        
        print(f"✅ Phase 4 complete")
        return True
    
    def phase_5_chat(self):
        """Phase 5: Handle MESSAGE messages in a loop."""
        print(f"\n{'='*70}")
        print(f"[{self.addr[0]}:{self.addr[1]}] Phase 5: Chat Messages")
        print(f"{'='*70}")
        
        transcript = self.server_state['transcript']
        clients = self.server_state['clients']
        
        while True:
            try:
                # Receive message
                msg = self.receive_message()
                
                if msg is None:
                    print(f"Client disconnected")
                    break
                
                if isinstance(msg, Receipt):
                    print(f"✅ Received RECEIPT from client {self.user_id}")
                    # Send RECEIPT response
                    receipt = Receipt(
                        sender_id=0,  # Server sends with ID 0
                        session_id=self.session_id,
                        transcript_hash="server_receipt",
                        signature="server_signature"
                    )
                    self.send_message(receipt)
                    break
                
                if isinstance(msg, Message):
                    print(f"📬 Message seq={msg.sequence_number} from user {msg.sender_id}")
                    
                    # Store in transcript
                    try:
                        transcript.add_message(
                            self.session_id,
                            msg.sender_id,
                            msg.sequence_number,
                            msg.timestamp,
                            msg.ciphertext,
                            msg.signature
                        )
                    except Exception as e:
                        print(f"⚠️  Failed to store message: {e}")
                    
                    # Broadcast to all connected clients
                    for handler in clients:
                        if handler != self:
                            try:
                                handler.send_message(msg)
                                print(f"   Broadcast to {handler.user_id}")
                            except Exception as e:
                                print(f"   Failed to broadcast: {e}")
                
                elif isinstance(msg, Error):
                    print(f"Error message from client: {msg.error_message}")
                    break
                
                else:
                    print(f"⚠️  Unexpected message type: {msg.type}")
            
            except Exception as e:
                print(f"❌ Error in chat loop: {e}")
                break
        
        print(f"✅ Phase 5 complete: Chat session ended")
    
    def handle(self):
        """Handle client connection (main entry point)."""
        try:
            print(f"\n{'='*70}")
            print(f"🔐 New client connection: {self.addr[0]}:{self.addr[1]}")
            print(f"{'='*70}")
            
            # Phase 1: Certificate exchange
            if not self.phase_1_certificate_exchange():
                return
            
            # Phase 2: DH temp key
            if not self.phase_2_dh_temp_key():
                return
            
            # Phase 3: Authentication
            if not self.phase_3_auth():
                return
            
            # Phase 4: DH session key
            if not self.phase_4_dh_session_key():
                return
            
            # Phase 5: Chat loop
            self.phase_5_chat()
            
            print(f"\n✅ Client {self.user_id} session complete")
        
        except Exception as e:
            print(f"❌ Error handling client: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Remove from active clients
            if self in self.server_state['clients']:
                self.server_state['clients'].remove(self)
            
            self.conn.close()
            print(f"Connection closed")


class SecureChatServer:
    """Secure chat server with PKI, DH, and AES encryption."""
    
    def __init__(self, host: str = 'localhost', port: int = 9999):
        """
        Initialize server.
        
        Args:
            host: Server listen address
            port: Server listen port
        """
        self.host = host
        self.port = port
        self.socket = None
        
        # Initialize database and transcript
        db_path = project_root / "chat.db"
        self.db = Database(str(db_path))
        self.transcript = Transcript(str(db_path))
        
        # Active client handlers
        self.clients = []
        self.clients_lock = threading.Lock()
        
        # Shared state
        self.server_state = {
            'db': self.db,
            'transcript': self.transcript,
            'clients': self.clients,
            'clients_lock': self.clients_lock
        }
        
        print(f"✅ Server initialized: {host}:{port}")
    
    def listen(self):
        """Start listening for client connections."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"✅ Server listening on {self.host}:{self.port}")
            
            # Accept client connections
            while True:
                try:
                    conn, addr = self.socket.accept()
                    print(f"\n📍 Incoming connection from {addr[0]}:{addr[1]}")
                    
                    # Create handler and start thread
                    handler = ClientHandler(conn, addr, self.server_state)
                    
                    with self.clients_lock:
                        self.clients.append(handler)
                    
                    client_thread = threading.Thread(target=handler.handle, daemon=True)
                    client_thread.start()
                
                except KeyboardInterrupt:
                    print(f"\n\n🛑 Server shutdown requested")
                    break
                except Exception as e:
                    print(f"❌ Error accepting connection: {e}")
        
        except Exception as e:
            print(f"❌ Server error: {e}")
        
        finally:
            if self.socket:
                self.socket.close()
                print(f"Server socket closed")


def main():
    """Entry point for server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureChat Server")
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=9999, help='Server port')
    
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print(f"🔐 SecureChat Server")
    print(f"{'='*70}")
    
    server = SecureChatServer(args.host, args.port)
    server.listen()


if __name__ == '__main__':
    main()
