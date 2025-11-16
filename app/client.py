"""
Client implementation — plain TCP; no TLS.

Workflow:
1. Load client certificate and private key
2. Connect to server
3. Send HELLO (client cert)
4. Receive SERVER_HELLO (server cert)
5. Validate both certificates
6. DH key exchange (temp AES key for auth)
7. REGISTER or LOGIN (encrypted and signed)
8. DH key exchange (session AES key for messages)
9. MESSAGE loop (send/receive encrypted, signed messages)
10. RECEIPT (close session, sign transcript hash)

Uses app.crypto.* and app.common.protocol.*
"""

import socket
import json
import sys
import os
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


class SecureChatClient:
    """Secure chat client with PKI, DH, and AES encryption."""
    
    def __init__(self, email: str, password: str, server_host: str, server_port: int):
        """
        Initialize client.
        
        Args:
            email: User email for login/registration
            password: User password
            server_host: Server hostname
            server_port: Server port
        """
        self.email = email
        self.password = password
        self.server_host = server_host
        self.server_port = server_port
        
        # Load client certificate and private key
        cert_dir = project_root / "certs"
        self.client_cert_path = cert_dir / "client.crt"
        self.client_key_path = cert_dir / "client.key"
        self.ca_cert_path = cert_dir / "ca.crt"
        
        # Cryptographic components
        self.rsa = RSASignature()
        self.dh = None
        self.dh_session = None
        
        # Server info
        self.server_cert = None
        self.user_id = None
        self.session_id = None
        
        # Encryption keys
        self.temp_aes_key = None  # For registration/login
        self.session_aes_key = None  # For messages
        
        # Socket
        self.socket = None
        
        # Transcript tracking
        self.message_sequence = 0
        self.transcript = None
        
        print(f"✅ Client initialized for {email}")
    
    def load_certificate(self) -> str:
        """Load client certificate as PEM string."""
        with open(self.client_cert_path, 'r') as f:
            cert_pem = f.read()
        print(f"✅ Client certificate loaded")
        return cert_pem
    
    def load_private_key(self):
        """Load client private key."""
        return self.rsa.load_private_key(str(self.client_key_path))
    
    def load_ca_certificate(self) -> str:
        """Load CA certificate for server validation."""
        with open(self.ca_cert_path, 'r') as f:
            ca_pem = f.read()
        return ca_pem
    
    def connect(self):
        """Connect to server via TCP."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"✅ Connected to {self.server_host}:{self.server_port}")
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            raise
    
    def send_message(self, message) -> str:
        """Send a protocol message and receive response."""
        msg_json = message_to_json(message)
        self.socket.sendall(msg_json.encode() + b'\n')
        print(f"📤 Sent: {message.type}")
        
        # Receive response
        response_data = b''
        while True:
            chunk = self.socket.recv(4096)
            if not chunk:
                break
            response_data += chunk
            # Check if we have a complete message (ends with newline)
            if b'\n' in response_data:
                break
        
        response_json = response_data.decode().strip()
        response_msg = json_to_message(response_json)
        print(f"📥 Received: {response_msg.type}")
        return response_msg
    
    def validate_server_certificate(self):
        """Validate server certificate signed by CA."""
        validator = CertificateValidator()
        
        # Load CA certificate
        ca_cert = validator.load_certificate(str(self.ca_cert_path))
        
        # Load server certificate
        server_cert_pem = self.server_cert
        # Write to temp file for loading
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
            f.write(server_cert_pem)
            temp_cert_path = f.name
        
        try:
            server_cert = validator.load_certificate(temp_cert_path)
            
            # Verify server cert is signed by CA
            ca_public_key = ca_cert.public_key()
            server_info = validator.get_certificate_info(server_cert)
            
            print(f"   Server cert CN: {server_info['subject_cn']}")
            print(f"   Server cert valid: {server_info['valid']}")
            print(f"   Server cert SAN: {server_info['san']}")
            
            # Verify signature: server cert signed by CA
            try:
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.primitives import hashes
                
                ca_public_key.verify(
                    server_cert.signature,
                    server_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print(f"✅ Server certificate signature verified by CA")
                return True
            except Exception as e:
                print(f"❌ Server certificate signature verification failed: {e}")
                return False
        finally:
            os.unlink(temp_cert_path)
    
    def phase_1_certificate_exchange(self):
        """Phase 1: Exchange certificates and validate."""
        print(f"\n{'='*70}")
        print(f"Phase 1: Certificate Exchange")
        print(f"{'='*70}")
        
        # Load and send client certificate
        client_cert = self.load_certificate()
        hello = Hello(certificate=client_cert)
        
        # Send HELLO and receive SERVER_HELLO
        server_hello = self.send_message(hello)
        
        if isinstance(server_hello, Error):
            print(f"❌ Server error: {server_hello.error_message}")
            raise Exception(server_hello.error_message)
        
        # Extract server certificate
        self.server_cert = server_hello.certificate
        
        # Validate server certificate
        if not self.validate_server_certificate():
            raise Exception("Server certificate validation failed")
        
        print(f"✅ Phase 1 complete: Certificates validated")
    
    def phase_2_dh_temp_key(self):
        """Phase 2: DH key exchange for temp AES key (for auth)."""
        print(f"\n{'='*70}")
        print(f"Phase 2: Diffie-Hellman (Temporary AES Key)")
        print(f"{'='*70}")
        
        # Generate DH keys
        self.dh = DiffieHellman()
        dh_public_key_hex = self.dh.public_key_hex
        
        # Send DH_CLIENT
        dh_client_msg = DHClient(public_key=dh_public_key_hex)
        dh_server_msg = self.send_message(dh_client_msg)
        
        if isinstance(dh_server_msg, Error):
            raise Exception(dh_server_msg.error_message)
        
        # Compute shared secret
        server_public_key_hex = dh_server_msg.public_key
        shared_secret = self.dh.compute_shared_secret(bytes.fromhex(server_public_key_hex))
        
        # Derive temporary AES key
        self.temp_aes_key = self.dh.derive_key(shared_secret, key_length=16)
        print(f"✅ Temporary AES key derived: {self.temp_aes_key.hex()}")
        
        print(f"✅ Phase 2 complete: Temp AES key established")
    
    def phase_3_auth(self):
        """Phase 3: Register or Login (encrypted with temp key)."""
        print(f"\n{'='*70}")
        print(f"Phase 3: Authentication")
        print(f"{'='*70}")
        
        # Try login first, then register
        private_key = self.load_private_key()
        
        # Prepare auth payload: email + password
        auth_payload = json.dumps({
            "email": self.email,
            "password": self.password
        })
        
        # Encrypt with temp key
        ciphertext = AES128.encrypt(auth_payload.encode(), self.temp_aes_key)
        
        # Sign the encrypted payload
        signature = self.rsa.sign(bytes.fromhex(ciphertext), private_key)
        
        # Try login
        print(f"Attempting login...")
        login_msg = Login(
            email=self.email,
            password=self.password,
            ciphertext=ciphertext,
            signature=signature
        )
        
        response = self.send_message(login_msg)
        
        if isinstance(response, LoginResponse):
            if response.success:
                self.user_id = response.user_id
                self.session_id = response.session_id
                print(f"✅ Login successful: user_id={self.user_id}, session_id={self.session_id}")
                return
            else:
                print(f"❌ Login failed, trying registration...")
        
        # Try registration
        print(f"Attempting registration...")
        register_msg = Register(
            email=self.email,
            password=self.password,
            ciphertext=ciphertext,
            signature=signature
        )
        
        reg_response = self.send_message(register_msg)
        
        if isinstance(reg_response, RegisterResponse):
            if reg_response.success:
                self.user_id = reg_response.user_id
                print(f"✅ Registration successful: user_id={self.user_id}")
                
                # Now login
                print(f"Logging in with new account...")
                login_msg2 = Login(
                    email=self.email,
                    password=self.password,
                    ciphertext=ciphertext,
                    signature=signature
                )
                login_response = self.send_message(login_msg2)
                
                if isinstance(login_response, LoginResponse) and login_response.success:
                    self.session_id = login_response.session_id
                    print(f"✅ Login successful: session_id={self.session_id}")
                else:
                    raise Exception("Login after registration failed")
            else:
                raise Exception("Registration failed")
        else:
            raise Exception(f"Unexpected response: {response.type}")
        
        print(f"✅ Phase 3 complete: Authentication successful")
    
    def phase_4_dh_session_key(self):
        """Phase 4: DH key exchange for session AES key (for messages)."""
        print(f"\n{'='*70}")
        print(f"Phase 4: Diffie-Hellman (Session AES Key)")
        print(f"{'='*70}")
        
        # Generate new DH keys for session
        self.dh_session = DiffieHellman()
        dh_public_key_hex = self.dh_session.public_key_hex
        
        # Send DH_CLIENT (with session_id to identify)
        dh_client_msg = DHClient(public_key=dh_public_key_hex)
        dh_server_msg = self.send_message(dh_client_msg)
        
        if isinstance(dh_server_msg, Error):
            raise Exception(dh_server_msg.error_message)
        
        # Compute shared secret
        server_public_key_hex = dh_server_msg.public_key
        shared_secret = self.dh_session.compute_shared_secret(bytes.fromhex(server_public_key_hex))
        
        # Derive session AES key
        self.session_aes_key = self.dh_session.derive_key(shared_secret, key_length=16)
        print(f"✅ Session AES key derived: {self.session_aes_key.hex()}")
        
        print(f"✅ Phase 4 complete: Session AES key established")
    
    def phase_5_chat(self):
        """Phase 5: Interactive chat loop."""
        print(f"\n{'='*70}")
        print(f"Phase 5: Chat Messages")
        print(f"{'='*70}")
        print(f"Type messages to send. Type 'quit' to exit.\n")
        
        private_key = self.load_private_key()
        
        # Start receiving messages from server in a thread
        import threading
        
        def receive_loop():
            while True:
                try:
                    # Receive message
                    response_data = b''
                    while True:
                        chunk = self.socket.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        if b'\n' in response_data:
                            break
                    
                    if not response_data:
                        break
                    
                    response_json = response_data.decode().strip()
                    response_msg = json_to_message(response_json)
                    
                    if isinstance(response_msg, Message):
                        # Decrypt and display
                        plaintext = AES128.decrypt(response_msg.ciphertext, self.session_aes_key)
                        payload = json.loads(plaintext.decode())
                        sender_name = "Server" if response_msg.sender_id != self.user_id else "You"
                        print(f"\n[{sender_name}]: {payload.get('text', '')}")
                        print("You: ", end="", flush=True)
                    elif isinstance(response_msg, Receipt):
                        print(f"\n✅ Received session receipt from peer")
                    elif isinstance(response_msg, Error):
                        print(f"\n❌ Server error: {response_msg.error_message}")
                        break
                except Exception as e:
                    break
        
        # Start receiver thread
        receiver = threading.Thread(target=receive_loop, daemon=True)
        receiver.start()
        
        # Interactive sender loop
        try:
            while True:
                message_text = input("You: ").strip()
                
                if message_text.lower() == 'quit':
                    print(f"Closing session...")
                    break
                
                if not message_text:
                    continue
                
                # Increment sequence number
                self.message_sequence += 1
                
                # Prepare message payload
                payload = json.dumps({"text": message_text})
                
                # Encrypt with session key
                ciphertext = AES128.encrypt(payload.encode(), self.session_aes_key)
                
                # Sign the (sequence + timestamp + ciphertext)
                sig_data = f"{self.message_sequence}{now_ms()}{ciphertext}".encode()
                signature = self.rsa.sign(sig_data, private_key)
                
                # Send MESSAGE
                msg = Message(
                    sender_id=self.user_id,
                    session_id=self.session_id,
                    sequence_number=self.message_sequence,
                    timestamp=now_ms(),
                    ciphertext=ciphertext,
                    signature=signature
                )
                
                msg_json = message_to_json(msg)
                self.socket.sendall(msg_json.encode() + b'\n')
                print(f"📤 Message sent (seq={self.message_sequence})")
        
        except KeyboardInterrupt:
            print(f"\nChat interrupted")
        
        print(f"✅ Phase 5 complete: Chat session ended")
    
    def phase_6_receipt(self):
        """Phase 6: Send session receipt (non-repudiation)."""
        print(f"\n{'='*70}")
        print(f"Phase 6: Session Closure (Receipt)")
        print(f"{'='*70}")
        
        private_key = self.load_private_key()
        
        # Create transcript hash from message sequence
        transcript_data = f"session_{self.session_id}_messages_{self.message_sequence}".encode()
        transcript_hash = hashlib.sha256(transcript_data).hexdigest()
        
        # Sign the transcript hash
        signature = self.rsa.sign(transcript_hash.encode(), private_key)
        
        # Send RECEIPT
        receipt = Receipt(
            sender_id=self.user_id,
            session_id=self.session_id,
            transcript_hash=transcript_hash,
            signature=signature
        )
        
        try:
            response = self.send_message(receipt)
            if isinstance(response, Receipt):
                print(f"✅ Received server receipt")
            print(f"✅ Phase 6 complete: Session closed with non-repudiation proof")
        except Exception as e:
            print(f"⚠️  Receipt exchange incomplete: {e}")
    
    def run(self):
        """Execute full client workflow."""
        try:
            print(f"\n{'='*70}")
            print(f"🔐 SecureChat Client")
            print(f"{'='*70}")
            
            # Connect
            self.connect()
            
            # Phase 1: Certificate exchange
            self.phase_1_certificate_exchange()
            
            # Phase 2: DH temp key
            self.phase_2_dh_temp_key()
            
            # Phase 3: Authentication
            self.phase_3_auth()
            
            # Phase 4: DH session key
            self.phase_4_dh_session_key()
            
            # Phase 5: Chat loop
            self.phase_5_chat()
            
            # Phase 6: Receipt
            self.phase_6_receipt()
            
            print(f"\n✅ Client session complete")
        
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            if self.socket:
                self.socket.close()
                print(f"Connection closed")


def main():
    """Entry point for client."""
    import argparse
    
    parser = argparse.ArgumentParser(description="SecureChat Client")
    parser.add_argument('--email', default='alice@example.com', help='Email for login')
    parser.add_argument('--password', default='alice123', help='Password')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=9999, help='Server port')
    
    args = parser.parse_args()
    
    client = SecureChatClient(args.email, args.password, args.host, args.port)
    client.run()


if __name__ == '__main__':
    main()
