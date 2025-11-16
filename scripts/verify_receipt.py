#!/usr/bin/env python3
"""
Offline verification tool for session receipts
Verifies transcript integrity and RSA signatures
"""

import sys
import json
import hashlib
import base64
from utils.crypto_utils import load_certificate, rsa_verify, pem_string_to_cert

def verify_message_signature(seqno, ts, ct, sig, cert):
    """Verify individual message signature"""
    # Recompute digest
    data = f"{seqno}{ts}{ct}".encode('utf-8')
    digest = hashlib.sha256(data).digest()
    
    # Verify signature
    return rsa_verify(digest, sig, cert)

def verify_transcript_and_receipt(transcript_file, receipt_file, cert_file):
    """
    Verify transcript integrity and receipt signature
    
    Args:
        transcript_file: Path to transcript file
        receipt_file: Path to receipt JSON file
        cert_file: Path to signer's certificate
    """
    
    print("="*60)
    print("SecureChat Receipt Verification Tool")
    print("="*60)
    
    # Load certificate
    print(f"\n[*] Loading certificate: {cert_file}")
    try:
        cert = load_certificate(cert_file)
        print("[✓] Certificate loaded")
    except Exception as e:
        print(f"[!] Failed to load certificate: {e}")
        return False
    
    # Load receipt
    print(f"\n[*] Loading receipt: {receipt_file}")
    try:
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
        print("[✓] Receipt loaded")
        print(f"    Peer: {receipt['peer']}")
        print(f"    Sequence range: {receipt['first_seq']} - {receipt['last_seq']}")
        print(f"    Transcript hash: {receipt['transcript_sha256']}")
    except Exception as e:
        print(f"[!] Failed to load receipt: {e}")
        return False
    
    # Verify transcript file hash
    print(f"\n[*] Verifying transcript: {transcript_file}")
    try:
        with open(transcript_file, 'rb') as f:
            transcript_data = f.read()
        
        computed_hash = hashlib.sha256(transcript_data).hexdigest()
        claimed_hash = receipt['transcript_sha256']
        
        if computed_hash == claimed_hash:
            print("[✓] Transcript hash matches receipt")
        else:
            print("[!] TAMPERED: Transcript hash does NOT match receipt!")
            print(f"    Claimed:  {claimed_hash}")
            print(f"    Computed: {computed_hash}")
            return False
    except Exception as e:
        print(f"[!] Failed to read transcript: {e}")
        return False
    
    # Verify receipt signature
    print("\n[*] Verifying receipt signature")
    try:
        receipt_sig = receipt['sig']
        signed_data = receipt['transcript_sha256'].encode('utf-8')
        
        if rsa_verify(signed_data, receipt_sig, cert):
            print("[✓] Receipt signature is VALID")
        else:
            print("[!] Receipt signature is INVALID!")
            return False
    except Exception as e:
        print(f"[!] Signature verification failed: {e}")
        return False
    
    # Verify individual messages
    print("\n[*] Verifying individual message signatures")
    try:
        lines = transcript_data.decode('utf-8').strip().split('\n')
        total_messages = len(lines)
        valid_messages = 0
        
        for i, line in enumerate(lines, 1):
            parts = line.split('|')
            if len(parts) != 5:
                print(f"[!] Line {i}: Invalid format")
                continue
            
            seqno, ts, ct, sig, peer_fp = parts
            seqno = int(seqno)
            ts = int(ts)
            
            if verify_message_signature(seqno, ts, ct, sig, cert):
                valid_messages += 1
                print(f"[✓] Message {i}/{total_messages} (seq={seqno}): Valid signature")
            else:
                print(f"[!] Message {i}/{total_messages} (seq={seqno}): INVALID signature!")
        
        print(f"\n[*] Verified {valid_messages}/{total_messages} messages")
        
        if valid_messages == total_messages:
            print("[✓] All message signatures are valid")
        else:
            print(f"[!] {total_messages - valid_messages} messages have invalid signatures")
            return False
    
    except Exception as e:
        print(f"[!] Failed to verify messages: {e}")
        return False
    
    print("\n" + "="*60)
    print("[✓] VERIFICATION SUCCESSFUL")
    print("All signatures are valid and transcript is intact.")
    print("="*60)
    
    return True

def main():
    if len(sys.argv) != 4:
        print("Usage: python verify_receipt.py <transcript_file> <receipt_file> <cert_file>")
        print("\nExample:")
        print("  python verify_receipt.py \\")
        print("    transcripts/client_user@email.com_1234567890.txt \\")
        print("    transcripts/client_user@email.com_1234567890_receipt.json \\")
        print("    certs/client_cert.pem")
        sys.exit(1)
    
    transcript_file = sys.argv[1]
    receipt_file = sys.argv[2]
    cert_file = sys.argv[3]
    
    success = verify_transcript_and_receipt(transcript_file, receipt_file, cert_file)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
