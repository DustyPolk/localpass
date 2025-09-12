# Security Interface Contract

**Feature**: 001-create-a-secure  
**Contract Type**: Security Operations  
**Date**: 2025-09-11

## Cryptographic Operations Contract

This contract defines the security interfaces and guarantees for all cryptographic operations in the password manager.

## Master Password Operations

### `hash_master_password(password: str) -> str`
Hash a master password for secure storage.

**Input Contract**:
```python
password: str  # Must be 8-128 characters, UTF-8 encoded
```

**Output Contract**:
```python
hash_string: str  # Argon2id hash string, always 97 characters
# Format: $argon2id$v=19$m=102400,t=8,p=8$<salt>$<hash>
```

**Security Guarantees**:
- Uses Argon2id algorithm with current parameters
- Generates cryptographically secure 32-byte salt
- Memory cost: 100MB (102400 KiB)
- Time cost: 8 iterations
- Parallelism: 8 threads
- Hash length: 32 bytes (256 bits)

**Error Conditions**:
- `ValueError`: Password length outside 8-128 range
- `UnicodeError`: Password contains invalid UTF-8
- `SystemError`: Insufficient memory for hashing

### `verify_master_password(password: str, hash_string: str) -> bool`
Verify a password against stored hash.

**Input Contract**:
```python
password: str       # Candidate password
hash_string: str   # Stored Argon2id hash
```

**Output Contract**:
```python
is_valid: bool     # True if password matches, False otherwise
```

**Security Guarantees**:
- Uses constant-time comparison
- No timing side-channel leakage
- Handles malformed hashes safely

**Error Conditions**:
- `ValueError`: Malformed hash string
- Never raises on incorrect password (returns False)

## Key Derivation Operations

### `derive_database_key(password: str, salt: bytes) -> tuple[bytes, bytes]`
Derive encryption key from master password.

**Input Contract**:
```python
password: str     # Master password (8-128 chars)
salt: bytes      # Optional salt (if None, generates new 32-byte salt)
```

**Output Contract**:
```python
(key: bytes, salt: bytes)
# key: 32 bytes (AES-256 key)
# salt: 32 bytes (used for derivation)
```

**Security Guarantees**:
- Uses PBKDF2-HMAC-SHA256
- 600,000 iterations (OWASP 2025 recommendation)
- Cryptographically secure salt generation
- Deterministic output for same password+salt

**Error Conditions**:
- `ValueError`: Invalid password or salt length
- `SystemError`: PBKDF2 derivation failure

### `derive_session_key(master_key: bytes, context: bytes) -> bytes`
Derive session-specific key from master key.

**Input Contract**:
```python
master_key: bytes  # 32-byte master key
context: bytes    # Context string for key separation
```

**Output Contract**:
```python
session_key: bytes  # 32-byte derived key
```

**Security Guarantees**:
- Uses HKDF-SHA256 for key derivation
- Context prevents key reuse across purposes
- No key material leakage between contexts

## Password Encryption Operations

### `encrypt_password(plaintext: str, key: bytes) -> str`
Encrypt password data with authenticated encryption.

**Input Contract**:
```python
plaintext: str   # Password text (1-1024 chars)
key: bytes      # 32-byte AES-256 key
```

**Output Contract**:
```python
encrypted_data: str  # JSON string containing:
# {
#   "nonce": "base64-encoded-nonce",
#   "ciphertext": "base64-encoded-ciphertext",
#   "tag": "base64-encoded-auth-tag",
#   "algorithm": "AES-256-GCM"
# }
```

**Security Guarantees**:
- Uses AES-256-GCM authenticated encryption
- Generates unique 96-bit nonce per encryption
- Provides both confidentiality and authenticity
- No key or nonce reuse

**Error Conditions**:
- `ValueError`: Invalid key length or empty plaintext
- `EncryptionError`: GCM encryption failure

### `decrypt_password(encrypted_data: str, key: bytes) -> str`
Decrypt and verify password data.

**Input Contract**:
```python
encrypted_data: str  # JSON from encrypt_password
key: bytes          # 32-byte AES-256 key
```

**Output Contract**:
```python
plaintext: str      # Decrypted password
```

**Security Guarantees**:
- Verifies authentication tag before decryption
- Fails fast on tampering detection
- Constant-time verification where possible

**Error Conditions**:
- `ValueError`: Malformed encrypted data JSON
- `DecryptionError`: Authentication failure or wrong key
- `IntegrityError`: Data corruption detected

## Session Security Operations

### `create_session(username: str, derived_key: bytes) -> Session`
Create authenticated session with timeout.

**Input Contract**:
```python
username: str     # Authenticated username
derived_key: bytes # 32-byte database encryption key
```

**Output Contract**:
```python
session: Session  # Session object with:
# - id: UUID4 string
# - username: str
# - created_at: datetime
# - expires_at: datetime (15 min default)
# - derived_key: bytes (memory only)
```

**Security Guarantees**:
- Cryptographically secure session ID generation
- Key stored only in memory (not on disk)
- Automatic expiration tracking
- Single active session per user

### `validate_session(session_id: str) -> Optional[Session]`
Validate active session and check timeout.

**Input Contract**:
```python
session_id: str   # UUID4 session identifier
```

**Output Contract**:
```python
session: Optional[Session]  # Valid session or None if expired/invalid
```

**Security Guarantees**:
- Constant-time session lookup
- Automatic cleanup of expired sessions
- No session extension on validation

## Memory Security Operations

### `secure_zero(data: Union[bytearray, memoryview]) -> None`
Securely zero sensitive data in memory.

**Input Contract**:
```python
data: bytearray | memoryview  # Mutable memory buffer
```

**Security Guarantees**:
- Overwrites memory with zeros
- Uses memory barriers to prevent optimization
- Works with Python bytearray and memoryview
- Best-effort security (Python limitations apply)

**Limitations**:
- Cannot guarantee complete memory wiping in Python
- String objects are immutable and may leave copies
- OS swap files may contain sensitive data
- Garbage collector may not respect clearing

### `secure_compare(a: bytes, b: bytes) -> bool`
Constant-time comparison for sensitive data.

**Input Contract**:
```python
a: bytes  # First value to compare
b: bytes  # Second value to compare  
```

**Output Contract**:
```python
equal: bool  # True if equal, False otherwise
```

**Security Guarantees**:
- Timing-attack resistant comparison
- Always processes full length of both inputs
- No early termination on mismatch

## Random Number Generation

### `generate_salt(length: int = 32) -> bytes`
Generate cryptographically secure random salt.

**Input Contract**:
```python
length: int  # Salt length in bytes (default: 32)
```

**Output Contract**:
```python
salt: bytes  # Cryptographically secure random bytes
```

**Security Guarantees**:
- Uses os.urandom() or equivalent secure source
- Suitable for cryptographic purposes
- Sufficient entropy for key derivation

### `generate_secure_password(length: int, charset: str) -> str`
Generate cryptographically secure password.

**Input Contract**:
```python
length: int    # Password length (8-128)
charset: str   # Character set to use
```

**Output Contract**:
```python
password: str  # Generated secure password
```

**Security Guarantees**:
- Cryptographically secure randomness
- Even distribution across character set
- No predictable patterns

## Database Security Operations

### `encrypt_database_field(data: str, session_key: bytes) -> str`
Encrypt sensitive database fields.

**Input Contract**:
```python
data: str          # Plaintext field data
session_key: bytes # Session-derived encryption key
```

**Output Contract**:
```python
encrypted_field: str  # Encrypted JSON string
```

**Security Guarantees**:
- Same as encrypt_password (AES-256-GCM)
- Unique nonce per field encryption
- Session-specific key isolation

### `verify_database_integrity(entries: List[dict]) -> bool`
Verify database has not been tampered with.

**Input Contract**:
```python
entries: List[dict]  # All password entries from database
```

**Output Contract**:
```python
is_valid: bool  # True if integrity check passes
```

**Security Guarantees**:
- Detects unauthorized database modifications
- Verifies encryption format consistency
- Checks for data corruption

## Error Handling Security

### Error Information Disclosure
**Guarantee**: Error messages never contain:
- Partial passwords or keys
- Salt values or nonces  
- Internal cryptographic state
- Database paths or structure details

**Practice**: All errors provide minimal information necessary for debugging while preserving security.

### Timing Attack Prevention
**Guarantee**: Security operations use constant-time algorithms where possible:
- Password verification
- Session validation
- Cryptographic comparisons
- Key derivation (inherently variable time, but consistent for same parameters)

## Security Boundaries

### What This Contract Guarantees
- Cryptographic operations follow current best practices
- Keys and sensitive data handled securely within Python constraints
- Authenticated encryption prevents tampering
- Constant-time operations prevent timing attacks
- Secure random number generation for all cryptographic purposes

### What This Contract Cannot Guarantee
- Complete memory wiping (Python garbage collection limitations)
- Protection against privileged memory access (OS kernel, debugging)
- Prevention of memory swapping to disk
- Side-channel attack resistance in all scenarios
- Hardware-level security (secure enclaves, HSMs)

### Threat Model
**Protected Against**:
- Eavesdropping on stored data
- Database tampering
- Brute force password attacks
- Timing-based side channels (limited)
- Unauthorized session access

**Not Protected Against**:
- Physical memory extraction
- Operating system compromise
- Hardware keyloggers
- Social engineering
- Quantum computing attacks (future threat)

This security contract provides clear guarantees and limitations for all cryptographic operations while acknowledging the inherent constraints of Python-based implementations.