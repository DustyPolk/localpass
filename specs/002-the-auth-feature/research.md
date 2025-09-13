# Research: Fix and Secure 15-Minute Authentication Session

**Feature Branch**: `002-the-auth-feature`  
**Date**: 2025-01-12  
**Status**: Complete

## Executive Summary

Research into the existing LocalPass codebase reveals that session management components exist but lack proper persistence across CLI invocations. The current implementation creates sessions in memory but doesn't persist them between command executions, making the 15-minute timeout feature non-functional. The fix requires implementing secure session persistence while maintaining security requirements.

## Current Implementation Analysis

### Existing Components

1. **Session Model** (`src/models/session.py`)
   - Decision: Keep existing Session dataclass
   - Rationale: Well-structured with proper validation and timeout calculation
   - Alternatives considered: Full rewrite - rejected as current model is sound

2. **SessionService** (`src/services/session_service.py`)
   - Decision: Extend to add persistence layer
   - Rationale: Core logic is correct, only lacks persistence
   - Alternatives considered: Replace with new service - unnecessary complexity

3. **AuthenticationService** (`src/services/auth_service.py`)
   - Decision: Minimal modifications for session retrieval
   - Rationale: Authentication flow is correct, just needs session lookup
   - Alternatives considered: None - current design is appropriate

### Key Issues Identified

1. **No Session Persistence**
   - Current: Sessions exist only in memory during single command execution
   - Required: Sessions must persist across CLI invocations for 15 minutes
   - Solution: Implement secure file-based session storage

2. **Missing Session Validation on Each Command**
   - Current: No check for existing valid sessions
   - Required: Each command should check for and use existing sessions
   - Solution: Add session validation decorator for commands

3. **No Audit Logging**
   - Current: No authentication event logging
   - Required: FR-009 requires security audit logging
   - Solution: Implement audit log service with file-based storage

## Security Considerations Research

### Session Storage Security

**Decision**: Use file-based session storage with encryption
**Rationale**: 
- CLI applications can't maintain memory state between invocations
- File storage is standard for CLI session management (e.g., SSH, GPG)
- Encryption prevents session hijacking

**Alternatives considered**:
- System keyring: Too complex, platform-specific issues
- Database storage: Overkill for single session
- Plain text files: Security risk

### Session Token Security

**Decision**: Use cryptographically secure random tokens
**Rationale**: 
- UUID4 provides 122 bits of randomness
- Standard practice for session identifiers
- Already used in current Session model

**Alternatives considered**:
- JWT tokens: Unnecessary complexity for local CLI
- Signed cookies: Not applicable to CLI context

### Memory Security

**Decision**: Clear sensitive data using bytearray and explicit zeroing
**Rationale**:
- Python's garbage collection doesn't guarantee immediate clearing
- bytearray allows in-place modification
- Industry best practice for password managers

**Alternatives considered**:
- ctypes SecureString: Platform-specific
- mlock/munlock: Requires elevated privileges

## Implementation Approach

### Session Persistence Layer

**Decision**: Implement XDG-compliant session file storage
**Rationale**:
- Follows platform conventions (XDG on Linux, ~/Library on macOS, %APPDATA% on Windows)
- Single file for single-user application
- Easy to clear on logout or timeout

**File Location**:
- Linux: `~/.local/share/localpass/session.enc`
- macOS: `~/Library/Application Support/localpass/session.enc`
- Windows: `%APPDATA%\localpass\session.enc`

### Session File Format

**Decision**: Encrypted JSON with session data
**Rationale**:
- JSON is human-debuggable before encryption
- Standard library support
- Easy to extend with additional fields

**Structure**:
```json
{
  "session_id": "uuid4",
  "username": "user",
  "created_at": "ISO-8601",
  "last_activity_at": "ISO-8601",
  "expires_at": "ISO-8601"
}
```

### Audit Logging

**Decision**: Append-only JSON Lines format
**Rationale**:
- Each line is valid JSON (easy parsing)
- Append-only prevents tampering
- Standard format for log aggregation

**File Location**: `~/.local/share/localpass/audit.log`

## Test Strategy Research

### Integration Test Approach

**Decision**: Use pytest with real file system
**Rationale**:
- Tests actual file permissions and platform behavior
- Catches platform-specific issues
- More reliable than mocks

### Security Test Cases

Priority test scenarios:
1. Session timeout after 15 minutes
2. Session extension on activity
3. Session file encryption/decryption
4. Memory clearing verification
5. Concurrent session handling
6. System time change resilience

## Platform Compatibility

### File System Considerations

**Decision**: Use pathlib and platformdirs library
**Rationale**:
- Handles platform differences automatically
- Well-tested, standard solution
- Already used in similar projects

### Time Handling

**Decision**: Use UTC internally, local time for display
**Rationale**:
- Prevents timezone issues
- Standard practice for session management
- Handles DST transitions correctly

## Performance Considerations

### Session Validation Performance

**Target**: <10ms for session validation
**Approach**:
- Cache decrypted session in memory during command execution
- Lazy loading of session file
- Fast path for missing session file

### Memory Clearing Performance

**Target**: <1ms for clearing sensitive data
**Approach**:
- Use bytearray for all sensitive data
- Explicit zeroing before deallocation
- Minimal allocation of sensitive strings

## Clarifications Resolved

1. **Session timeout configuration**
   - Decision: Fixed 15-minute timeout as specified
   - Future: Can add configuration in later version

2. **System sleep/hibernate behavior**
   - Decision: Timer continues during sleep (security-first approach)
   - Rationale: Prevents indefinite sessions if laptop closed

## Dependencies Required

No new dependencies needed. Current stack sufficient:
- `cryptography`: For session file encryption
- `pathlib`: For cross-platform file paths
- Standard library `json`, `datetime`, `uuid`

## Risk Analysis

### Security Risks
1. **Session file theft**: Mitigated by encryption
2. **Memory dumps**: Mitigated by secure clearing
3. **Time manipulation**: Mitigated by max session duration

### Implementation Risks
1. **Platform differences**: Mitigated by platformdirs
2. **File permissions**: Explicit 0600 mode for session file
3. **Concurrent access**: Single-user app, low risk

## Recommendations

1. Implement session persistence first (highest priority)
2. Add audit logging second (compliance requirement)
3. Enhance memory security third (defense in depth)
4. Document security considerations for users

## Next Steps (Phase 1)

1. Design enhanced Session model with persistence
2. Create contracts for session operations
3. Design audit log schema
4. Create quickstart guide for testing
5. Generate contract tests

---

*Research completed: 2025-01-12*
*All NEEDS CLARIFICATION items resolved*