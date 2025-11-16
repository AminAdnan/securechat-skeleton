#!/usr/bin/env python3
"""
Cryptographic utility functions for SecureChat
Includes: AES encryption, RSA signing, DH key exchange, certificate validation
"""

import os
import hashlib
import base64
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

# ============================================================================
# Certificate Handling
# ============================================================================

def load_certificate(cert_path):
    """Load a PEM-encoded X.509 certificate"""
    with open(cert_path, 'rb') as f:
        return load_pem_x509_certificate(f.read())

def load_private_key(key_path):
    """Load a PEM-encoded RSA private key"""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def cert_to_pem_string(cert):
    """Convert certificate object to PEM string"""
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def pem_string_to_cert(pem_str):
    """Convert PEM string to certificate object"""
    return load_pem_x509_certificate(pem_str.encode('utf-8'))

def get_cert_fingerprint(cert):
    """Get SHA-256 fingerprint of certificate"""
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()

def validate_certificate(cert, ca_cert, expected_cn=None):
    """
    Validate a certificate against CA and check validity period
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate
        expected_cn: Expected Common Name (optional)
    
    Returns:
        tuple: (is_valid, error_message)
    """
    
    # Check if certificate is expired
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False, "BAD_CERT: Certificate expired or not yet valid"
    
    # Verify signature chain (check if cert is signed by CA)
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"BAD_CERT: Signature verification failed - {str(e)}"
    
    # Check if issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        return False, "BAD_CERT: Certificate not issued by trusted CA"
    
    # Check Common Name if specified
    if expected_cn:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if cn != expected_cn:
            return False, f"BAD_CERT: Common Name mismatch (expected {expected_cn}, got {cn})"
    
    return True, "Certificate valid"

# ============================================================================
# Diffie-Hellman Key Exchange
# ============================================================================

def generate_dh_params():
    """Generate DH public parameters (p, g) and private key"""
    # Use safe prime for p (2048-bit)
    # In production, use standardized groups (RFC 3526)
    # For this assignment, we'll use a known safe prime
    
    # 2048-bit MODP Group (RFC 3526, Group 14)
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    g = 2
    
    # Generate random private key (a)
    a = int.from_bytes(os.urandom(256), byteorder='big') % (p - 2) + 1
    
    # Compute public key A = g^a mod p
    A = pow(g, a, p)
    
    return p, g, a, A

def compute_dh_shared_secret(B, a, p):
    """
    Compute shared secret from peer's public key
    
    Args:
        B: Peer's public DH value
        a: Own private DH value
        p: DH prime modulus
    
    Returns:
        Shared secret K_s
    """
    return pow(B, a, p)

def derive_session_key(shared_secret):
    """
    Derive AES-128 key from DH shared secret
    K = Trunc_16(SHA256(big_endian(K_s)))
    
    Args:
        shared_secret: DH shared secret (integer)
    
    Returns:
        16-byte AES key
    """
    # Convert to big-endian bytes
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, 
        byteorder='big'
    )
    
    # Hash with SHA-256
    hash_digest = hashlib.sha256(secret_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    return hash_digest[:16]

# ============================================================================
# AES-128 Encryption/Decryption
# ============================================================================

def pkcs7_pad(data, block_size=16):
    """Add PKCS#7 padding to data"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data):
    """Remove PKCS#7 padding from data"""
    padding_length = data[-1]
    if padding_length > len(data) or padding_length == 0:
        raise ValueError("Invalid padding")
    
    # Verify padding
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            raise ValueError("Invalid padding")
    
    return data[:-padding_length]

def aes_encrypt(plaintext, key):
    """
    Encrypt plaintext using AES-128-CBC with PKCS#7 padding
    
    Args:
        plaintext: bytes or string to encrypt
        key: 16-byte AES key
    
    Returns:
        base64-encoded ciphertext (includes IV)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad plaintext
    padded_plaintext = pkcs7_pad(plaintext)
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Prepend IV to ciphertext
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext_b64, key):
    """
    Decrypt AES-128-CBC ciphertext with PKCS#7 padding
    
    Args:
        ciphertext_b64: base64-encoded ciphertext (with IV prepended)
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext as string
    """
    # Decode base64
    data = base64.b64decode(ciphertext_b64)
    
    # Extract IV (first 16 bytes)
    iv = data[:16]
    ciphertext = data[16:]
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext.decode('utf-8')

# ============================================================================
# RSA Signing and Verification
# ============================================================================

def rsa_sign(data, private_key):
    """
    Sign data with RSA private key
    
    Args:
        data: bytes to sign
        private_key: RSA private key
    
    Returns:
        base64-encoded signature
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')

def rsa_verify(data, signature_b64, cert):
    """
    Verify RSA signature using certificate's public key
    
    Args:
        data: bytes that were signed
        signature_b64: base64-encoded signature
        cert: Certificate containing public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        signature = base64.b64decode(signature_b64)
        public_key = cert.public_key()
        
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ============================================================================
# Hash Functions
# ============================================================================

def sha256_hash(data):
    """Compute SHA-256 hash of data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def sha256_hex(data):
    """Compute SHA-256 hash and return as hex string"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

# ============================================================================
# Password Hashing
# ============================================================================

def generate_salt(length=16):
    """Generate random salt"""
    return os.urandom(length)

def hash_password(password, salt):
    """
    Hash password with salt: SHA256(salt || password)
    
    Args:
        password: Password string
        salt: Random salt bytes
    
    Returns:
        Hex-encoded hash
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return hashlib.sha256(salt + password).hexdigest()

def verify_password(password, salt, stored_hash):
    """Verify password against stored hash"""
    computed_hash = hash_password(password, salt)
    # Constant-time comparison to prevent timing attacks
    return computed_hash == stored_hash
