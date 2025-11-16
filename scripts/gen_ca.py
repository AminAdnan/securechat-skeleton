#!/usr/bin/env python3
"""
Generate a self-signed Root Certificate Authority (CA)
This CA will be used to sign server and client certificates
"""

import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

def generate_ca():
    """Generate a self-signed root CA certificate"""
    
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    # Generate RSA private key for CA
    print("[*] Generating CA private key (2048-bit RSA)...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create CA certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Build the CA certificate
    print("[*] Building self-signed CA certificate...")
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # Valid for 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    # Write CA private key to file
    ca_key_path = "certs/ca_key.pem"
    print(f"[*] Writing CA private key to {ca_key_path}...")
    with open(ca_key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write CA certificate to file
    ca_cert_path = "certs/ca_cert.pem"
    print(f"[*] Writing CA certificate to {ca_cert_path}...")
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n[✓] Root CA generated successfully!")
    print(f"    CA Certificate: {ca_cert_path}")
    print(f"    CA Private Key: {ca_key_path}")
    print("\n[!] IMPORTANT: Keep ca_key.pem secure and never commit to git!")
    
    return ca_cert, ca_private_key

if __name__ == "__main__":
    print("="*60)
    print("SecureChat Root CA Generator")
    print("="*60)
    generate_ca()
