# SecureChat - Encrypted Console Chat System

A comprehensive secure chat implementation demonstrating cryptographic primitives including PKI, AES-128, RSA signatures, Diffie-Hellman key exchange, and non-repudiation mechanisms.

**Assignment:** Information Security Assignment #2  
**Course:** Fall 2025, FAST-NUCES  
**GitHub Repository:** [Your Fork URL]

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Security Features](#security-features)
- [File Structure](#file-structure)
- [Protocol Phases](#protocol-phases)

---

## Features

✅ **PKI (Public Key Infrastructure)**
- Self-signed Root CA
- X.509 certificate generation and validation
- Mutual certificate authentication

✅ **Secure Authentication**
- User registration with salted password hashing
- Encrypted credential transmission
- MySQL database for credential storage

✅ **Key Agreement**
- Diffie-Hellman key exchange
- Session-specific AES-128 keys

✅ **Encrypted Communication**
- AES-128-CBC encryption with PKCS#7 padding
- Per-message RSA signatures
- Replay attack protection (sequence numbers)
- Timestamp-based freshness validation

✅ **Non-Repudiation**
- Append-only message transcripts
- Digitally signed session receipts
- Offline verification tools

---

## Architecture

```
┌─────────┐                    ┌─────────┐
│ Client  │◄──────────────────►│ Server  │
└─────────┘  Encrypted Chat    └─────────┘
     │                              │
     │                              │
     ▼                              ▼
┌──────────────┐            ┌──────────────┐
│  Client Cert │            │ Server Cert  │
│  (CA-signed) │            │ (CA-signed)  │
└──────────────┘            └──────────────┘
         │                          │
         └──────────┬───────────────┘
                    ▼
            ┌──────────────┐
            │   Root CA    │
            └──────────────┘
```

---

## Prerequisites

- Python 3.8+
- MySQL Server 8.0+
- Required Python packages (see `requirements.txt`)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/securechat-skeleton.git
cd securechat-skeleton
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv

# Activate:
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up MySQL Database

```sql
CREATE DATABASE securechat;
USE securechat;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 5. Generate PKI Infrastructure

```bash
# Generate Root CA
python scripts/gen_ca.py

# Generate Server and Client Certificates
python scripts/gen_cert.py
```

---

## Configuration

### Database Configuration

Create a `.env` file in the project root:

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=securechat
```

**⚠️ Never commit `.env` to version control!**

---

## Usage

### Starting the Server

```bash
python server.py
```

Expected output:
```
[✓] Server initialized
[*] Server listening on 0.0.0.0:5000
```

### Running the Client

```bash
python client.py
```

#### Registration Flow

```
[*] Authentication
1. Register new user
2. Login with existing account
Choose option (1/2): 1
Email: alice@example.com
Username: alice
Password: ********
[✓] Registration successful
```

#### Login and Chat

```
Choose option (1/2): 2
Email: alice@example.com
Password: ********
[✓] Login successful

Secure Chat Session Started
Type your messages below. Type 'quit' to exit.

You: Hello, this is a secure message!
[✓] Message sent
You: quit
```

---

## Testing

### 1. Wireshark Packet Capture

Start Wireshark and capture on `localhost` (loopback interface):

```
Filter: tcp.port == 5000
```

**Verify:**
- No plaintext passwords visible
- All chat messages are encrypted (base64 ciphertext only)

### 2. Certificate Validation Test

#### Test Expired Certificate

Modify `scripts/gen_cert.py` to create an expired certificate:

```python
.not_valid_after(
    datetime.utcnow() - timedelta(days=1)  # Expired yesterday
)
```

Regenerate and test:
```bash
python scripts/gen_cert.py
python client.py
```

Expected output:
```
[!] BAD_CERT: Certificate expired or not yet valid
```

#### Test Self-Signed Certificate

Replace server certificate with a self-signed one:

```bash
# Create self-signed cert (not CA-signed)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/fake_key.pem \
  -out certs/fake_cert.pem \
  -days 365 -subj "/CN=fake"
```

Replace `server_cert.pem` temporarily and test.

Expected output:
```
[!] BAD_CERT: Signature verification failed
```

### 3. Tampering Detection Test

```bash
# Run a chat session first to generate a transcript
python client.py
# ... send some messages ...

# Create tampered version
python scripts/test_tampering.py transcripts/client_alice_1234567890.txt

# Verify original (should pass)
python scripts/verify_receipt.py \
  transcripts/client_alice_1234567890.txt \
  transcripts/client_alice_1234567890_receipt.json \
  certs/client_cert.pem

# Verify tampered (should fail)
python scripts/verify_receipt.py \
  transcripts/client_alice_1234567890_TAMPERED.txt \
  transcripts/client_alice_1234567890_receipt.json \
  certs/client_cert.pem
```

Expected output for tampered:
```
[!] TAMPERED: Transcript hash does NOT match receipt!
[!] Message 1/5: INVALID signature!
```

### 4. Replay Attack Test

Manually test by modifying `client.py` to send a duplicate message with the same sequence number:

```python
# Send message twice with same seqno
self.send_message("Test")
self.seqno -= 1  # Revert seqno
self.send_message("Replay attempt")
```

Expected server output:
```
[!] REPLAY: Invalid sequence number
```

---

## Security Features

### Confidentiality
- **AES-128-CBC** encryption for all messages
- **PKCS#7 padding** for block cipher
- **Unique IV** for each encryption

### Integrity
- **SHA-256** message digests
- **RSA signatures** on all messages
- **Transcript hashing** for session evidence

### Authenticity
- **X.509 certificates** for entity authentication
- **CA-signed certificates** verified against trusted root
- **Mutual authentication** (both client and server verify)

### Non-Repudiation
- **Per-message RSA signatures** (cannot deny sending)
- **Append-only transcripts** with cert fingerprints
- **Signed session receipts** for audit trail
- **Offline verification** tools provided

### Freshness & Replay Protection
- **Sequence numbers** (strictly increasing)
- **Timestamps** (5-minute window)
- **Nonces** in authentication handshake

---

## File Structure

```
securechat-skeleton/
├── certs/                      # PKI certificates (not in git)
│   ├── ca_cert.pem
│   ├── ca_key.pem
│   ├── server_cert.pem
│   ├── server_key.pem
│   ├── client_cert.pem
│   └── client_key.pem
├── scripts/
│   ├── gen_ca.py              # Generate root CA
│   ├── gen_cert.py            # Generate certificates
│   ├── verify_receipt.py      # Offline verification
│   └── test_tampering.py      # Tampering test
├── utils/
│   ├── crypto_utils.py        # Crypto primitives
│   └── db_utils.py            # Database operations
├── protocol/
│   └── messages.py            # Protocol message formats
├── transcripts/               # Session transcripts (not in git)
├── server.py                  # Server application
├── client.py                  # Client application
├── requirements.txt           # Python dependencies
├── .env.example               # Environment template
├── .gitignore                 # Git ignore rules
└── README.md                  # This file
```

---

## Protocol Phases

### Phase 1: Control Plane (Certificate Exchange)

1. Client sends `HELLO` with client certificate
2. Server validates certificate against CA
3. Server responds with `SERVER_HELLO` and server certificate
4. Client validates server certificate

### Phase 2: Temporary DH for Authentication

1. Client initiates DH exchange (sends `g`, `p`, `A`)
2. Server responds with `B`
3. Both compute shared secret `K_s`
4. Derive temporary AES key: `K = Trunc16(SHA256(K_s))`

### Phase 3: Authentication

#### Registration:
- Client sends encrypted: `email`, `username`, `SHA256(salt||password)`, `salt`
- Server stores in database

#### Login:
- Client sends encrypted: `email`, `password_hash`
- Server retrieves stored salt, recomputes hash, validates

### Phase 4: Session Key Establishment

1. New DH exchange (post-authentication)
2. Derive session-specific AES-128 key

### Phase 5: Encrypted Messaging

For each message:
1. Encrypt with AES-128: `ct = AES(plaintext, K)`
2. Compute digest: `h = SHA256(seqno || ts || ct)`
3. Sign digest: `sig = RSA_SIGN(h, private_key)`
4. Send: `{seqno, ts, ct, sig}`

Recipient verifies:
1. Check `seqno` is increasing (replay protection)
2. Verify timestamp is fresh
3. Verify signature: `RSA_VERIFY(h, sig, peer_cert)`
4. Decrypt: `plaintext = AES_DECRYPT(ct, K)`

### Phase 6: Session Closure

1. Generate transcript: `seqno|ts|ct|sig|cert_fp`
2. Compute transcript hash: `SHA256(transcript)`
3. Sign hash: `receipt_sig = RSA_SIGN(transcript_hash)`
4. Save `SessionReceipt` with signature

---

## Sample Input/Output

### Certificate Inspection

```bash
openssl x509 -in certs/server_cert.pem -text -noout
```

Output:
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: ...
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = SecureChat Root CA, O = FAST-NUCES SecureChat
        Validity
            Not Before: Nov 15 00:00:00 2025 GMT
            Not After : Nov 15 00:00:00 2026 GMT
        Subject: CN = localhost, O = FAST-NUCES SecureChat
        ...
```

### Message Format (Encrypted)

```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1700000000000,
  "ct": "SGVsbG8gV29ybGQhCg==...",
  "sig": "dGhpcyBpcyBhIHNpZ25hdHVyZQ==..."
}
```

### Session Receipt

```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "a3f5b9c2...",
  "sig": "signature_of_hash..."
}
```

---

## Troubleshooting

### Connection Refused

Ensure server is running:
```bash
python server.py
```

### Certificate Errors

Regenerate PKI:
```bash
python scripts/gen_ca.py
python scripts/gen_cert.py
```

### Database Connection Errors

Verify MySQL is running and `.env` is configured correctly:
```bash
mysql -u root -p
> SHOW DATABASES;
```

---

## Contributors

- **Student Name:** [Amin Adnan]
- **Roll Number:** [22i-0816]


---


