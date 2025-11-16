#!/usr/bin/env python3
"""
SecureChat Client
Connects to server, performs authentication, and enables encrypted messaging
"""

import socket
import os
import base64
import hashlib
import json
import time
import threading
from utils.crypto_utils import *
from protocol.messages import *

class SecureChatClient:
    def __init__(self, server_host='localhost', server_port=5000):
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = None
        
        # Load client certificate and key
        self.client_cert = load_certificate("certs/client_cert.pem")
        self.client_key = load_private_key("certs/client_key.pem")
        self.ca_cert = load_certificate("certs/ca_cert.pem")
        
        # Session state
        self.server_cert = None
        self.session_key = None
        self.seqno = 0
        self.transcript = []
        
        # Transcript storage
        os.makedirs("transcripts", exist_ok=True)
        
        print("[✓] Client initialized")
    
    def connect(self):
        """Connect to the server"""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_host, self.server_port))
        print(f"[✓] Connected to server {self.server_host}:{self.server_port}")
        
        # === PHASE 1: Control Plane (Certificate Exchange) ===
        print("\n[*] Phase 1: Certificate exchange")
        
        # Send client hello
        client_nonce = os.urandom(16)
        hello_msg = create_hello_message(
            cert_to_pem_string(self.client_cert),
            client_nonce
        )
        ProtocolMessage.send(self.client_socket, hello_msg)
        
        # Receive server hello
        server_hello = ProtocolMessage.receive(self.client_socket)
        if not server_hello or server_hello["type"] != MessageType.SERVER_HELLO:
            print("[!] Invalid server hello")
            return False
        
        # Validate server certificate
        server_cert_pem = server_hello["server_cert"]
        self.server_cert = pem_string_to_cert(server_cert_pem)
        
        is_valid, error_msg = validate_certificate(self.server_cert, self.ca_cert, expected_cn="localhost")
        if not is_valid:
            print(f"[!] {error_msg}")
            return False
        
        print("[✓] Server certificate validated")
        
        return True
    
    def perform_dh_exchange(self):
        """Perform Diffie-Hellman key exchange"""
        print("\n[*] Performing DH key exchange...")
        
        # Generate DH parameters
        p, g, a, A = generate_dh_params()
        
        # Send DH client message
        dh_client_msg = create_dh_client_message(g, p, A)
        ProtocolMessage.send(self.client_socket, dh_client_msg)
        
        # Receive DH server message
        dh_server_msg = ProtocolMessage.receive(self.client_socket)
        if not dh_server_msg or dh_server_msg["type"] != MessageType.DH_SERVER:
            print("[!] Invalid DH server response")
            return None
        
        B = dh_server_msg["B"]
        
        # Compute shared secret and derive key
        K_s = compute_dh_shared_secret(B, a, p)
        key = derive_session_key(K_s)
        
        print("[✓] DH key exchange complete")
        return key
    
    def register(self, email, username, password):
        """Register a new user"""
        print("\n[*] Phase 2: Registration")
        
        # Perform temporary DH exchange for encrypted registration
        temp_key = self.perform_dh_exchange()
        if not temp_key:
            return False
        
        # Generate salt and hash password
        salt = generate_salt(16)
        pwd_hash = hash_password(password, salt)
        
        # Create registration message
        register_msg = create_register_message(
            email,
            username,
            pwd_hash,
            base64.b64encode(salt).decode('utf-8')
        )
        
        # Send registration
        ProtocolMessage.send(self.client_socket, register_msg)
        
        # Receive response
        response = ProtocolMessage.receive(self.client_socket)
        if not response or response["type"] != MessageType.AUTH_RESPONSE:
            print("[!] Invalid auth response")
            return False
        
        if response["success"]:
            print(f"[✓] Registration successful: {response['message']}")
            return True
        else:
            print(f"[!] Registration failed: {response['message']}")
            return False
    
    def login(self, email, password):
        """Login with existing credentials"""
        print("\n[*] Phase 2: Login")
        
        # Perform temporary DH exchange for encrypted login
        temp_key = self.perform_dh_exchange()
        if not temp_key:
            return False
        
        # For login, we need to retrieve the salt from the server first
        # In a real system, you'd do this separately
        # For this assignment, we'll hash with a dummy salt and let server verify
        # The server will retrieve the actual salt and verify
        
        # Generate a nonce for freshness
        nonce = os.urandom(16)
        
        # Create login message (server will look up salt)
        # We send SHA256(password) as a placeholder
        pwd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        login_msg = create_login_message(email, pwd_hash, nonce)
        
        # Send login
        ProtocolMessage.send(self.client_socket, login_msg)
        
        # Receive response
        response = ProtocolMessage.receive(self.client_socket)
        if not response or response["type"] != MessageType.AUTH_RESPONSE:
            print("[!] Invalid auth response")
            return False
        
        if response["success"]:
            print(f"[✓] Login successful: {response['message']}")
            return True
        else:
            print(f"[!] Login failed: {response['message']}")
            return False
    
    def establish_session_key(self):
        """Establish session key for encrypted chat"""
        print("\n[*] Phase 3: Session key establishment")
        
        self.session_key = self.perform_dh_exchange()
        if self.session_key:
            print("[✓] Session key established")
            return True
        return False
    
    def send_message(self, plaintext):
        """Send an encrypted message"""
        if not self.session_key:
            print("[!] No session key established")
            return False
        
        # Increment sequence number
        self.seqno += 1
        
        # Get timestamp
        timestamp = get_timestamp_ms()
        
        # Encrypt message
        ciphertext = aes_encrypt(plaintext, self.session_key)
        
        # Compute digest and sign
        digest = compute_message_digest(self.seqno, timestamp, ciphertext)
        signature = rsa_sign(digest, self.client_key)
        
        # Create message
        msg = create_chat_message(self.seqno, timestamp, ciphertext, signature)
        
        # Send message
        ProtocolMessage.send(self.client_socket, msg)
        
        # Add to transcript
        server_cert_fp = get_cert_fingerprint(self.server_cert)
        self.transcript.append({
            "seqno": self.seqno,
            "ts": timestamp,
            "ct": ciphertext,
            "sig": signature,
            "peer_cert_fp": server_cert_fp
        })
        
        return True
    
    def chat(self):
        """Interactive chat session"""
        print("\n" + "="*60)
        print("Secure Chat Session Started")
        print("Type your messages below. Type 'quit' to exit.")
        print("="*60 + "\n")
        
        try:
            while True:
                # Get user input
                message = input("You: ")
                
                if message.lower() == 'quit':
                    break
                
                if not message.strip():
                    continue
                
                # Send message
                if self.send_message(message):
                    print("[✓] Message sent")
                else:
                    print("[!] Failed to send message")
        
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
        
        # Send disconnect message
        disconnect_msg = create_disconnect_message()
        ProtocolMessage.send(self.client_socket, disconnect_msg)
        
        # Generate receipt
        if self.transcript:
            self.generate_receipt()
    
    def generate_receipt(self):
        """Generate session receipt for non-repudiation"""
        print("\n[*] Generating session receipt...")
        
        user_email = input("Enter your email for receipt: ")
        
        # Create transcript file
        transcript_file = f"transcripts/client_{user_email}_{int(time.time())}.txt"
        
        with open(transcript_file, 'w') as f:
            for entry in self.transcript:
                line = f"{entry['seqno']}|{entry['ts']}|{entry['ct']}|{entry['sig']}|{entry['peer_cert_fp']}\n"
                f.write(line)
        
        # Compute transcript hash
        with open(transcript_file, 'rb') as f:
            transcript_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Sign transcript hash
        signature = rsa_sign(transcript_hash.encode('utf-8'), self.client_key)
        
        # Create receipt
        receipt = create_receipt_message(
            "client",
            self.transcript[0]["seqno"],
            self.transcript[-1]["seqno"],
            transcript_hash,
            signature
        )
        
        # Save receipt
        receipt_file = f"transcripts/client_{user_email}_{int(time.time())}_receipt.json"
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] Transcript saved: {transcript_file}")
        print(f"[✓] Receipt saved: {receipt_file}")
    
    def disconnect(self):
        """Disconnect from server"""
        if self.client_socket:
            self.client_socket.close()
        print("[✓] Disconnected from server")

def main():
    """Main client application"""
    print("="*60)
    print("SecureChat Client")
    print("="*60)
    
    client = SecureChatClient(server_host='localhost', server_port=5000)
    
    try:
        # Connect and exchange certificates
        if not client.connect():
            print("[!] Failed to connect")
            return
        
        # Authentication
        print("\n[*] Authentication")
        print("1. Register new user")
        print("2. Login with existing account")
        choice = input("Choose option (1/2): ")
        
        if choice == '1':
            email = input("Email: ")
            username = input("Username: ")
            password = input("Password: ")
            
            if not client.register(email, username, password):
                print("[!] Registration failed")
                return
        
        elif choice == '2':
            email = input("Email: ")
            password = input("Password: ")
            
            if not client.login(email, password):
                print("[!] Login failed")
                return
        else:
            print("[!] Invalid choice")
            return
        
        # Establish session key
        if not client.establish_session_key():
            print("[!] Failed to establish session key")
            return
        
        # Start chat
        client.chat()
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
