#!/usr/bin/env python3
"""
Protocol message definitions and serialization for SecureChat
"""

import json
import base64
import time

class MessageType:
    """Message type constants"""
    HELLO = "hello"
    SERVER_HELLO = "server_hello"
    REGISTER = "register"
    LOGIN = "login"
    AUTH_RESPONSE = "auth_response"
    DH_CLIENT = "dh_client"
    DH_SERVER = "dh_server"
    MSG = "msg"
    RECEIPT = "receipt"
    ERROR = "error"
    DISCONNECT = "disconnect"

class ProtocolMessage:
    """Base class for protocol messages"""
    
    @staticmethod
    def to_json(data):
        """Convert message dict to JSON string"""
        return json.dumps(data)
    
    @staticmethod
    def from_json(json_str):
        """Parse JSON string to message dict"""
        return json.loads(json_str)
    
    @staticmethod
    def send(sock, data):
        """Send a message over socket"""
        json_str = ProtocolMessage.to_json(data)
        message = json_str.encode('utf-8')
        
        # Send length prefix (4 bytes, big-endian)
        length = len(message)
        sock.sendall(length.to_bytes(4, byteorder='big'))
        
        # Send message
        sock.sendall(message)
    
    @staticmethod
    def receive(sock):
        """Receive a message from socket"""
        # Receive length prefix
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # Receive message
        chunks = []
        bytes_received = 0
        
        while bytes_received < length:
            chunk = sock.recv(min(length - bytes_received, 4096))
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_received += len(chunk)
        
        message = b''.join(chunks)
        return ProtocolMessage.from_json(message.decode('utf-8'))

# ============================================================================
# Control Plane Messages
# ============================================================================

def create_hello_message(client_cert_pem, nonce):
    """Create client hello message"""
    return {
        "type": MessageType.HELLO,
        "client_cert": client_cert_pem,
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }

def create_server_hello_message(server_cert_pem, nonce):
    """Create server hello message"""
    return {
        "type": MessageType.SERVER_HELLO,
        "server_cert": server_cert_pem,
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }

def create_register_message(email, username, pwd_hash_b64, salt_b64):
    """Create registration message"""
    return {
        "type": MessageType.REGISTER,
        "email": email,
        "username": username,
        "pwd": pwd_hash_b64,
        "salt": salt_b64
    }

def create_login_message(email, pwd_hash_b64, nonce):
    """Create login message"""
    return {
        "type": MessageType.LOGIN,
        "email": email,
        "pwd": pwd_hash_b64,
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }

def create_auth_response_message(success, message):
    """Create authentication response message"""
    return {
        "type": MessageType.AUTH_RESPONSE,
        "success": success,
        "message": message
    }

# ============================================================================
# Key Agreement Messages
# ============================================================================

def create_dh_client_message(g, p, A):
    """Create DH client message"""
    return {
        "type": MessageType.DH_CLIENT,
        "g": g,
        "p": p,
        "A": A
    }

def create_dh_server_message(B):
    """Create DH server message"""
    return {
        "type": MessageType.DH_SERVER,
        "B": B
    }

# ============================================================================
# Data Plane Messages
# ============================================================================

def create_chat_message(seqno, timestamp, ciphertext, signature):
    """
    Create encrypted chat message
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64-encoded ciphertext
        signature: Base64-encoded RSA signature
    """
    return {
        "type": MessageType.MSG,
        "seqno": seqno,
        "ts": timestamp,
        "ct": ciphertext,
        "sig": signature
    }

def compute_message_digest(seqno, timestamp, ciphertext):
    """
    Compute SHA-256 digest for message signing
    Format: seqno || timestamp || ciphertext
    """
    import hashlib
    
    data = f"{seqno}{timestamp}{ciphertext}".encode('utf-8')
    return hashlib.sha256(data).digest()

# ============================================================================
# Non-Repudiation Messages
# ============================================================================

def create_receipt_message(peer, first_seq, last_seq, transcript_hash, signature):
    """
    Create session receipt for non-repudiation
    
    Args:
        peer: "client" or "server"
        first_seq: First sequence number
        last_seq: Last sequence number
        transcript_hash: SHA-256 hash of transcript (hex)
        signature: Base64-encoded RSA signature of transcript_hash
    """
    return {
        "type": MessageType.RECEIPT,
        "peer": peer,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": signature
    }

# ============================================================================
# Utility Messages
# ============================================================================

def create_error_message(error_code, error_message):
    """Create error message"""
    return {
        "type": MessageType.ERROR,
        "code": error_code,
        "message": error_message
    }

def create_disconnect_message():
    """Create disconnect message"""
    return {
        "type": MessageType.DISCONNECT
    }

# ============================================================================
# Timestamp utilities
# ============================================================================

def get_timestamp_ms():
    """Get current Unix timestamp in milliseconds"""
    return int(time.time() * 1000)

def is_timestamp_fresh(ts_ms, max_age_seconds=300):
    """Check if timestamp is fresh (within max_age_seconds)"""
    current_ts = get_timestamp_ms()
    age_ms = current_ts - ts_ms
    return 0 <= age_ms <= (max_age_seconds * 1000)
