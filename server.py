#!/usr/bin/env python3
"""
SecureChat Server
Handles client connections, authentication, and encrypted messaging
"""

import socket
import os
import base64
import hashlib
import threading
from utils.crypto_utils import *
from utils.db_utils import get_db
from protocol.messages import *

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        
        # Load server certificate and key
        self.server_cert = load_certificate("certs/server_cert.pem")
        self.server_key = load_private_key("certs/server_key.pem")
        self.ca_cert = load_certificate("certs/ca_cert.pem")
        
        # Database
        self.db = get_db()
        self.db.connect()
        
        # Transcript storage
        os.makedirs("transcripts", exist_ok=True)
        
        print("[✓] Server initialized")
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"\n[+] New connection from {client_address}")
                
                # Handle client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            self.cleanup()
    
    def handle_client(self, client_socket, client_address):
        """Handle a single client connection"""
        
        client_cert = None
        session_key = None
        user_email = None
        seqno = 0
        transcript = []
        
        try:
            # === PHASE 1: Control Plane (Certificate Exchange) ===
            print(f"[{client_address}] Phase 1: Certificate exchange")
            
            # Receive client hello
            hello_msg = ProtocolMessage.receive(client_socket)
            if not hello_msg or hello_msg["type"] != MessageType.HELLO:
                self.send_error(client_socket, "BAD_HELLO", "Invalid hello message")
                return
            
            # Parse and validate client certificate
            client_cert_pem = hello_msg["client_cert"]
            client_cert = pem_string_to_cert(client_cert_pem)
            
            is_valid, error_msg = validate_certificate(client_cert, self.ca_cert)
            if not is_valid:
                self.send_error(client_socket, "BAD_CERT", error_msg)
                return
            
            print(f"[{client_address}] ✓ Client certificate validated")
            
            # Send server hello
            server_nonce = os.urandom(16)
            server_hello_msg = create_server_hello_message(
                cert_to_pem_string(self.server_cert),
                server_nonce
            )
            ProtocolMessage.send(client_socket, server_hello_msg)
            
            # === PHASE 2: Temporary DH for Registration/Login ===
            print(f"[{client_address}] Phase 2: Temporary DH key exchange")
            
            # Receive DH parameters from client
            dh_client_msg = ProtocolMessage.receive(client_socket)
            if not dh_client_msg or dh_client_msg["type"] != MessageType.DH_CLIENT:
                self.send_error(client_socket, "BAD_DH", "Invalid DH message")
                return
            
            p = dh_client_msg["p"]
            g = dh_client_msg["g"]
            A = dh_client_msg["A"]
            
            # Generate server's DH values
            b = int.from_bytes(os.urandom(256), byteorder='big') % (p - 2) + 1
            B = pow(g, b, p)
            
            # Send DH server response
            dh_server_msg = create_dh_server_message(B)
            ProtocolMessage.send(client_socket, dh_server_msg)
            
            # Compute shared secret and derive temporary key
            K_s = compute_dh_shared_secret(A, b, p)
            temp_key = derive_session_key(K_s)
            
            print(f"[{client_address}] ✓ Temporary session key established")
            
            # === PHASE 3: Registration or Login ===
            print(f"[{client_address}] Phase 3: Authentication")
            
            # Receive encrypted auth message
            auth_msg = ProtocolMessage.receive(client_socket)
            if not auth_msg:
                self.send_error(client_socket, "BAD_AUTH", "Invalid auth message")
                return
            
            auth_type = auth_msg["type"]
            
            if auth_type == MessageType.REGISTER:
                success, message = self.handle_registration(auth_msg, temp_key)
                user_email = auth_msg["email"] if success else None
            elif auth_type == MessageType.LOGIN:
                success, message, email = self.handle_login(auth_msg, temp_key)
                user_email = email if success else None
            else:
                success = False
                message = "Invalid authentication type"
            
            # Send auth response
            auth_response = create_auth_response_message(success, message)
            ProtocolMessage.send(client_socket, auth_response)
            
            if not success:
                print(f"[{client_address}] ✗ Authentication failed: {message}")
                return
            
            print(f"[{client_address}] ✓ Authentication successful: {user_email}")
            
            # === PHASE 4: Session DH Key Exchange ===
            print(f"[{client_address}] Phase 4: Session key exchange")
            
            # Receive new DH parameters from client
            dh_client_msg = ProtocolMessage.receive(client_socket)
            if not dh_client_msg or dh_client_msg["type"] != MessageType.DH_CLIENT:
                self.send_error(client_socket, "BAD_DH", "Invalid session DH")
                return
            
            p = dh_client_msg["p"]
            g = dh_client_msg["g"]
            A = dh_client_msg["A"]
            
            # Generate new server DH values
            b = int.from_bytes(os.urandom(256), byteorder='big') % (p - 2) + 1
            B = pow(g, b, p)
            
            # Send DH server response
            dh_server_msg = create_dh_server_message(B)
            ProtocolMessage.send(client_socket, dh_server_msg)
            
            # Compute shared secret and derive session key
            K_s = compute_dh_shared_secret(A, b, p)
            session_key = derive_session_key(K_s)
            
            print(f"[{client_address}] ✓ Session key established")
            
            # === PHASE 5: Encrypted Chat ===
            print(f"[{client_address}] Phase 5: Encrypted messaging")
            print(f"[{client_address}] Ready for secure communication")
            
            client_cert_fingerprint = get_cert_fingerprint(client_cert)
            
            while True:
                # Receive message
                msg = ProtocolMessage.receive(client_socket)
                if not msg:
                    break
                
                if msg["type"] == MessageType.DISCONNECT:
                    print(f"[{client_address}] Client disconnecting")
                    break
                
                if msg["type"] == MessageType.MSG:
                    # Validate message
                    msg_seqno = msg["seqno"]
                    msg_ts = msg["ts"]
                    msg_ct = msg["ct"]
                    msg_sig = msg["sig"]
                    
                    # Check sequence number (replay protection)
                    if msg_seqno <= seqno:
                        print(f"[{client_address}] ✗ REPLAY: Invalid sequence number")
                        continue
                    
                    # Check timestamp freshness
                    if not is_timestamp_fresh(msg_ts, max_age_seconds=300):
                        print(f"[{client_address}] ✗ STALE: Message too old")
                        continue
                    
                    # Verify signature
                    digest = compute_message_digest(msg_seqno, msg_ts, msg_ct)
                    if not rsa_verify(digest, msg_sig, client_cert):
                        print(f"[{client_address}] ✗ SIG_FAIL: Invalid signature")
                        continue
                    
                    # Decrypt message
                    try:
                        plaintext = aes_decrypt(msg_ct, session_key)
                        print(f"[{client_address}] Client: {plaintext}")
                    except Exception as e:
                        print(f"[{client_address}] ✗ Decryption failed: {e}")
                        continue
                    
                    # Update sequence number
                    seqno = msg_seqno
                    
                    # Add to transcript
                    transcript.append({
                        "seqno": msg_seqno,
                        "ts": msg_ts,
                        "ct": msg_ct,
                        "sig": msg_sig,
                        "peer_cert_fp": client_cert_fingerprint
                    })
            
            # === PHASE 6: Session Closure & Non-Repudiation ===
            print(f"[{client_address}] Phase 6: Generating session receipt")
            
            if transcript:
                self.generate_receipt(user_email, transcript, "server")
            
        except Exception as e:
            print(f"[{client_address}] Error: {e}")
        finally:
            client_socket.close()
            print(f"[{client_address}] Connection closed")
    
    def handle_registration(self, msg, temp_key):
        """Handle user registration"""
        email = msg["email"]
        username = msg["username"]
        salt_b64 = msg["salt"]
        pwd_hash_b64 = msg["pwd"]
        
        # Decode salt and password hash
        salt = base64.b64decode(salt_b64)
        pwd_hash = pwd_hash_b64
        
        # Register user in database
        success, message = self.db.register_user(email, username, salt, pwd_hash)
        return success, message
    
    def handle_login(self, msg, temp_key):
        """Handle user login"""
        email = msg["email"]
        pwd_hash = msg["pwd"]
        
        # Verify credentials
        success, message = self.db.verify_login(email, pwd_hash)
        return success, message, email
    
    def send_error(self, sock, code, message):
        """Send error message to client"""
        error_msg = create_error_message(code, message)
        try:
            ProtocolMessage.send(sock, error_msg)
        except:
            pass
    
    def generate_receipt(self, user_email, transcript, peer):
        """Generate session receipt for non-repudiation"""
        # Create transcript file
        transcript_file = f"transcripts/server_{user_email}_{int(time.time())}.txt"
        
        with open(transcript_file, 'w') as f:
            for entry in transcript:
                line = f"{entry['seqno']}|{entry['ts']}|{entry['ct']}|{entry['sig']}|{entry['peer_cert_fp']}\n"
                f.write(line)
        
        # Compute transcript hash
        with open(transcript_file, 'rb') as f:
            transcript_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Sign transcript hash
        signature = rsa_sign(transcript_hash.encode('utf-8'), self.server_key)
        
        # Create receipt
        receipt = create_receipt_message(
            peer,
            transcript[0]["seqno"],
            transcript[-1]["seqno"],
            transcript_hash,
            signature
        )
        
        # Save receipt
        receipt_file = f"transcripts/server_{user_email}_{int(time.time())}_receipt.json"
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] Receipt generated: {receipt_file}")
    
    def cleanup(self):
        """Cleanup resources"""
        if self.server_socket:
            self.server_socket.close()
        self.db.disconnect()

if __name__ == "__main__":
    server = SecureChatServer(host='0.0.0.0', port=5000)
    server.start()
