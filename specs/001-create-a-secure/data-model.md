# Data Model: Secure CLI Password Manager

**Feature**: 001-create-a-secure  
**Phase**: Design  
**Date**: 2025-09-11

## Entity Overview

The password manager maintains four primary entities that handle secure storage and access control for user credentials.

## Core Entities

### PasswordEntry
Represents a stored password record with full metadata and encryption.

**Attributes**:
- `id` (Integer, Primary Key): Unique identifier for database operations
- `service` (String, Required): Service name (e.g., "gmail", "github", "aws-console")
- `username` (String, Required): Username or email for the service
- `encrypted_password` (Text, Required): AES-256-GCM encrypted password data (JSON containing nonce, ciphertext, tag)
- `url` (String, Optional): Associated website or service URL
- `notes` (Text, Optional): Additional encrypted notes or metadata
- `created_at` (Timestamp, Auto): Entry creation timestamp
- `updated_at` (Timestamp, Auto): Last modification timestamp
- `password_strength` (String, Computed): Derived strength indicator ("Weak", "Medium", "Strong")

**Validation Rules**:
- Service name must be 1-100 characters, alphanumeric and common symbols only
- Username must be 1-255 characters
- Encrypted password must be valid JSON with required GCM fields
- URL must be valid HTTP/HTTPS if provided
- Notes limited to 1000 characters when decrypted

**Relationships**:
- Unique constraint on (service, username) combination
- Indexed by service for fast lookups
- Soft references to Session for audit logging

### MasterCredential
Represents the user's master authentication and encryption key management.

**Attributes**:
- `id` (Integer, Primary Key): Single record identifier (always 1)
- `username` (String, Required): User identifier for the password manager
- `password_hash` (String, Required): Argon2id hash of master password
- `salt` (Bytes, Required): Salt used for key derivation (32 bytes)
- `key_derivation_params` (JSON, Required): Parameters for PBKDF2 key derivation
- `created_at` (Timestamp, Auto): Master password creation date
- `last_auth_at` (Timestamp, Updated): Last successful authentication
- `auth_failure_count` (Integer, Default 0): Failed authentication attempts
- `locked_until` (Timestamp, Optional): Account lockout expiration

**Validation Rules**:
- Only one master credential record allowed
- Password hash must be valid Argon2id format
- Salt must be exactly 32 bytes
- Key derivation params must contain iterations, algorithm
- Lockout after 5 failed attempts for 15 minutes

**Security Features**:
- Master password never stored in plaintext
- Salt prevents rainbow table attacks
- Configurable key derivation parameters for future upgrades
- Account lockout protection against brute force

### Session
Represents an authenticated user session with timeout management.

**Attributes**:
- `id` (String, Primary Key): Unique session identifier (UUID4)
- `username` (String, Required): Associated user identifier
- `created_at` (Timestamp, Auto): Session creation time
- `last_activity_at` (Timestamp, Updated): Last operation timestamp
- `expires_at` (Timestamp, Required): Hard session expiration
- `derived_key` (Bytes, Memory Only): Database encryption key (never persisted)
- `is_active` (Boolean, Computed): Whether session is valid and not expired

**Validation Rules**:
- Session ID must be cryptographically random UUID4
- Idle timeout: 15 minutes (configurable)
- Maximum session duration: 4 hours
- Only one active session per user

**State Transitions**:
1. **Created**: Fresh session after successful authentication
2. **Active**: Session with recent activity within timeout window
3. **Idle**: Session with no activity but not yet expired
4. **Expired**: Session past timeout or maximum duration
5. **Terminated**: Explicitly logged out or invalidated

**Security Features**:
- Automatic timeout on inactivity
- Encryption key stored in memory only
- Session invalidation on suspicious activity

### DatabaseMetadata
Represents database configuration and integrity information.

**Attributes**:
- `id` (Integer, Primary Key): Single record identifier (always 1)
- `version` (String, Required): Database schema version
- `encryption_algorithm` (String, Required): Encryption algorithm identifier ("AES-256-GCM")
- `key_derivation_algorithm` (String, Required): KDF algorithm ("PBKDF2-SHA256")
- `created_at` (Timestamp, Auto): Database initialization timestamp
- `last_backup_at` (Timestamp, Optional): Last backup creation time
- `total_entries` (Integer, Computed): Count of password entries
- `integrity_hash` (String, Computed): Hash of all entry IDs for integrity checking

**Validation Rules**:
- Only one metadata record allowed
- Version must follow semantic versioning (MAJOR.MINOR.PATCH)
- Algorithm identifiers must match supported implementations
- Integrity hash must be SHA-256 of sorted entry IDs

**Migration Support**:
- Schema version enables database upgrades
- Algorithm fields support cryptographic upgrades
- Backup tracking for data safety

## Database Schema

### SQLite Implementation

```sql
-- Master credential (single record)
CREATE TABLE master_credential (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt BLOB NOT NULL CHECK (LENGTH(salt) = 32),
    key_derivation_params JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_auth_at TIMESTAMP,
    auth_failure_count INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Password entries
CREATE TABLE password_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    url TEXT,
    encrypted_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(service, username),
    CHECK (LENGTH(service) BETWEEN 1 AND 100),
    CHECK (LENGTH(username) BETWEEN 1 AND 255)
);

-- Database metadata (single record)
CREATE TABLE database_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version TEXT NOT NULL,
    encryption_algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    key_derivation_algorithm TEXT NOT NULL DEFAULT 'PBKDF2-SHA256',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_backup_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_password_entries_service ON password_entries(service);
CREATE INDEX idx_password_entries_updated_at ON password_entries(updated_at);

-- Triggers for updated_at maintenance
CREATE TRIGGER update_password_entries_timestamp 
    AFTER UPDATE ON password_entries
    BEGIN
        UPDATE password_entries 
        SET updated_at = CURRENT_TIMESTAMP 
        WHERE id = NEW.id;
    END;
```

## Encryption Schema

### Field-Level Encryption
Only sensitive fields are encrypted to maintain search functionality on service names and usernames.

**Encrypted Fields**:
- `password_entries.encrypted_password` - Always encrypted
- `password_entries.encrypted_notes` - Encrypted if present

**Encryption Format (JSON)**:
```json
{
    "nonce": "base64-encoded-nonce",
    "ciphertext": "base64-encoded-ciphertext", 
    "tag": "base64-encoded-auth-tag",
    "algorithm": "AES-256-GCM"
}
```

**Plaintext Fields**:
- Service names - Enable fast searching and filtering
- Usernames - Allow duplicate detection and user selection
- Timestamps - Support maintenance and auditing
- URLs - Enable integration and automation (non-sensitive)

## Data Access Patterns

### Read Operations
1. **List entries by service**: `SELECT * FROM password_entries WHERE service LIKE ?`
2. **Search by partial service**: `SELECT * FROM password_entries WHERE service GLOB ?`
3. **Get specific entry**: `SELECT * FROM password_entries WHERE service = ? AND username = ?`
4. **Recent entries**: `SELECT * FROM password_entries ORDER BY updated_at DESC LIMIT ?`

### Write Operations
1. **Add entry**: `INSERT INTO password_entries (service, username, encrypted_password, ...)`
2. **Update password**: `UPDATE password_entries SET encrypted_password = ?, updated_at = ? WHERE id = ?`
3. **Delete entry**: `DELETE FROM password_entries WHERE id = ?`

### Authentication Flow
1. **Verify master password**: Compare against `master_credential.password_hash`
2. **Derive database key**: Use stored salt and params from `master_credential`
3. **Create session**: Insert into memory-based session store
4. **Update activity**: Track last_auth_at and reset failure count

## Data Integrity

### Validation Rules
- **Referential Integrity**: Foreign key constraints where applicable
- **Data Constraints**: Check constraints on field lengths and formats
- **Unique Constraints**: Prevent duplicate service/username combinations
- **Timestamp Consistency**: created_at <= updated_at for all records

### Backup and Recovery
- **Atomic Operations**: All mutations within transactions
- **WAL Mode**: SQLite Write-Ahead Logging for concurrent read safety
- **Integrity Checks**: Periodic validation of encryption and data consistency
- **Export Format**: JSON export of decrypted data for migration

This data model provides a secure foundation for the password manager while maintaining simple, efficient access patterns and strong data integrity guarantees.