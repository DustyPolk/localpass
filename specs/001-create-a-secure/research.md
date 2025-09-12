# Research: Secure CLI Password Manager

**Feature**: 001-create-a-secure  
**Research Phase**: Complete  
**Date**: 2025-09-11

## Security Architecture Research

### Encryption Standards Decision
**Decision**: AES-256-GCM mode with PyCryptodome library  
**Rationale**: 
- Provides authenticated encryption (encryption + integrity)
- Stream cipher mode efficient for variable-length passwords
- No manual padding required
- GCM mode prevents tampering attacks
- PyCryptodome actively maintained (May 2025 release)

**Alternatives Considered**:
- AES-256-CBC: Requires manual padding and separate HMAC
- ChaCha20-Poly1305: Good alternative but less widely supported
- Fernet (cryptography library): Higher-level but less flexible

### Master Password Hashing Decision
**Decision**: Argon2id with high-security parameters  
**Rationale**:
- Winner of Password Hashing Competition
- Resistant to GPU and ASIC attacks
- Configurable memory cost (100MB+ for password managers)
- Recommended by OWASP and security experts
- Python argon2-cffi library well-maintained

**Parameters for Password Manager Use**:
```
time_cost=8        # Higher than web apps (2-4)
memory_cost=102400 # 100MB+ for offline tools
parallelism=8      # Utilize available cores
hash_len=32        # 256-bit output
salt_len=32        # 256-bit salt
```

**Alternatives Considered**:
- Scrypt: Good fallback, less memory-hard than Argon2
- PBKDF2: Older standard, vulnerable to GPU attacks
- bcrypt: Limited to 72-byte passwords

### Key Derivation Decision
**Decision**: PBKDF2 for master password → database key + HKDF for multiple keys  
**Rationale**:
- PBKDF2 with 600,000 iterations meets 2025 OWASP standards
- HKDF for deriving multiple keys from strong master key
- Separate keys for database encryption and session signing
- Allows key rotation without re-encrypting all data

### Database Encryption Decision
**Decision**: Field-level encryption with standard SQLite  
**Rationale**:
- No external dependencies (SQLCipher requires separate installation)
- Full control over encryption process
- Easier cross-platform deployment
- Can encrypt only sensitive fields (passwords)

**Alternatives Considered**:
- SQLCipher: Professional choice but adds deployment complexity
- Full database encryption: Overkill for single-user tool
- No encryption: Unacceptable for password manager

## CLI Interface Research

### CLI Framework Decision
**Decision**: Typer + Rich combination  
**Rationale**:
- Typer provides modern type-hint based CLI development
- Automatic help generation and validation
- Rich adds professional table formatting and colors
- Excellent cross-platform compatibility
- Built-in JSON output support for scripting
- Active development and maintenance

**Alternatives Considered**:
- Click: Good but more boilerplate than Typer
- argparse: Standard library but limited formatting
- Fire: Too magic, less control over interface

### Secure Input Decision
**Decision**: Enhanced getpass with validation and fallbacks  
**Rationale**:
- Built into Python standard library
- Cross-platform password masking
- Can add validation and confirmation prompts
- Handles edge cases (non-TTY environments)

### Output Formatting Decision
**Decision**: Dual-mode output (Rich tables for humans, JSON for scripts)  
**Rationale**:
- Rich tables provide excellent visual experience
- JSON output enables shell scripting integration
- Conditional formatting based on --format flag
- Professional appearance matches modern CLI tools

## Cross-Platform Considerations

### Path Management Decision
**Decision**: Platform-specific paths following OS conventions  
**Rationale**:
- Windows: %APPDATA%\LocalPass
- macOS: ~/Library/Application Support/LocalPass
- Linux: XDG Base Directory Specification
- Respects user expectations and OS security models

### Dependency Management Decision
**Decision**: Pure Python dependencies only  
**Rationale**:
- Avoids native compilation issues
- Easier installation across platforms
- cryptography library provides pre-built wheels
- Typer and Rich are pure Python

## Session Management Research

### Authentication Strategy Decision
**Decision**: Session timeout with master password re-authentication  
**Rationale**:
- 15-minute idle timeout balances security and usability
- No persistent session storage (memory only)
- Forces re-authentication for sensitive operations
- Simple implementation without token complexity

**Alternatives Considered**:
- JWT tokens: Overkill for single-user local application
- OS keyring integration: Adds complexity, limited benefit
- No timeout: Security risk for shared systems

### Memory Security Decision
**Decision**: bytearray with explicit zeroing + limitations acknowledgment  
**Rationale**:
- bytearray allows in-place modification and zeroing
- Python strings are immutable (copies may remain in memory)
- Best effort approach within Python's limitations
- Document security boundaries clearly

**Limitations Acknowledged**:
- Python garbage collection doesn't guarantee memory clearing
- OS may swap memory to disk
- String immutability means copies may exist
- Consider process isolation for maximum security

## Performance Requirements Research

### Performance Targets Decision
**Decision**: Sub-second response for all operations, <50MB memory usage  
**Rationale**:
- Password managers are interactive tools requiring fast response
- SQLite provides excellent single-user performance
- Encryption operations are fast with modern CPUs
- Memory usage should be minimal for background operation

### Scalability Decision
**Decision**: Optimize for hundreds of entries, single-user database  
**Rationale**:
- Personal password managers rarely exceed 1000 entries
- SQLite handles this scale excellently
- No need for complex indexing or sharding
- Simple schema design sufficient

## Testing Strategy Research

### Testing Framework Decision
**Decision**: pytest with fixture-based testing  
**Rationale**:
- Standard Python testing framework
- Excellent fixture support for database setup/teardown
- Rich plugin ecosystem
- Good CI/CD integration

### Testing Approach Decision
**Decision**: Contract tests → Integration tests → Unit tests  
**Rationale**:
- Contract tests ensure CLI interface stability
- Integration tests validate encryption/decryption flows
- Unit tests for business logic components
- Real SQLite database in tests (no mocking storage)

## Security Boundaries and Limitations

### Acknowledged Security Limitations
1. **Python Memory Management**: Cannot guarantee secure memory wiping
2. **Process Memory**: No protection against memory dumps by privileged processes
3. **Swap Files**: OS may swap sensitive data to disk
4. **Debug Information**: Debug builds may retain sensitive data longer

### Mitigation Strategies
1. **Explicit Memory Zeroing**: Use bytearray and zero on destruction
2. **Minimal Exposure Time**: Decrypt only when needed, clear immediately
3. **Process Isolation**: Run in dedicated process when possible
4. **User Education**: Document security boundaries in README

## Implementation Priority

### Phase 1: Core Security
1. Cryptographic primitives (encryption, hashing)
2. Secure key derivation
3. Database schema and encryption

### Phase 2: CLI Interface
1. Basic CRUD operations (add, get, update, delete, list)
2. Master password authentication
3. Secure input handling

### Phase 3: Enhanced Features
1. Rich output formatting
2. JSON output for scripting
3. Password generation
4. Search and filtering

### Phase 4: Polish
1. Cross-platform testing
2. Comprehensive error handling
3. Documentation and help text
4. Installation packaging

## Research Validation

All technical decisions have been validated against:
- ✅ OWASP password storage guidelines
- ✅ NIST cryptographic recommendations
- ✅ Python security best practices
- ✅ Cross-platform compatibility requirements
- ✅ Unix philosophy (do one thing well)
- ✅ Modern CLI user experience standards

**Research Status**: COMPLETE - Ready for Phase 1 Design