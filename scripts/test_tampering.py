#!/usr/bin/env python3
"""
Test script to demonstrate tampering detection
Modifies a transcript and shows that verification fails
"""

import sys
import os

def tamper_transcript(original_file):
    """
    Create a tampered version of the transcript
    """
    
    print("="*60)
    print("Tampering Detection Test")
    print("="*60)
    
    # Read original transcript
    print(f"\n[*] Reading original transcript: {original_file}")
    try:
        with open(original_file, 'r') as f:
            lines = f.readlines()
        print(f"[✓] Loaded {len(lines)} messages")
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        return None
    
    if len(lines) == 0:
        print("[!] Transcript is empty")
        return None
    
    # Create tampered version
    tampered_file = original_file.replace('.txt', '_TAMPERED.txt')
    
    print(f"\n[*] Creating tampered version: {tampered_file}")
    print("[*] Modification: Flipping one bit in the first ciphertext")
    
    # Tamper with the first line's ciphertext
    parts = lines[0].strip().split('|')
    if len(parts) != 5:
        print("[!] Invalid transcript format")
        return None
    
    seqno, ts, ct, sig, peer_fp = parts
    
    # Flip one bit in the ciphertext (change first character)
    if ct[0] == 'A':
        tampered_ct = 'B' + ct[1:]
    else:
        tampered_ct = 'A' + ct[1:]
    
    # Reconstruct tampered line
    lines[0] = f"{seqno}|{ts}|{tampered_ct}|{sig}|{peer_fp}\n"
    
    # Write tampered transcript
    try:
        with open(tampered_file, 'w') as f:
            f.writelines(lines)
        print(f"[✓] Tampered transcript created")
    except Exception as e:
        print(f"[!] Failed to write tampered file: {e}")
        return None
    
    print("\n[*] Tampering complete!")
    print(f"    Original: {original_file}")
    print(f"    Tampered: {tampered_file}")
    print("\n[*] Now run verify_receipt.py on the tampered file to see detection:")
    print(f"    python scripts/verify_receipt.py {tampered_file} <receipt_file> <cert_file>")
    
    return tampered_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_tampering.py <transcript_file>")
        print("\nExample:")
        print("  python test_tampering.py transcripts/client_user@email.com_1234567890.txt")
        sys.exit(1)
    
    transcript_file = sys.argv[1]
    
    if not os.path.exists(transcript_file):
        print(f"[!] File not found: {transcript_file}")
        sys.exit(1)
    
    tamper_transcript(transcript_file)

if __name__ == "__main__":
    main()
