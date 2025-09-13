# Quickstart: Testing 15-Minute Authentication Session

**Feature**: Fix and Secure 15-Minute Authentication Session  
**Branch**: `002-the-auth-feature`  
**Purpose**: Verify the authentication session properly maintains state for 15 minutes

## Prerequisites

1. Ensure LocalPass is installed:
```bash
uv pip install -e .
```

2. Initialize a test database:
```bash
localpass init --test-mode
# Use password: TestPass123!
```

## Test Scenarios

### Scenario 1: Basic Session Creation and Validation

```bash
# Step 1: Authenticate and create session
localpass login
# Enter: TestPass123!
# Expected: "Authentication successful. Session valid for 15 minutes."

# Step 2: Verify session persists (within 1 minute)
localpass status
# Expected: "Session active. Expires in 14 minutes."

# Step 3: List passwords without re-authentication
localpass list
# Expected: Password list displayed without password prompt
```

### Scenario 2: Session Timeout Extension

```bash
# Step 1: Login
localpass login
# Enter: TestPass123!

# Step 2: Wait 14 minutes (or modify system time)
sleep 840  # 14 minutes

# Step 3: Use a command to extend session
localpass list
# Expected: Command executes, session extended by 15 minutes

# Step 4: Check session status
localpass status
# Expected: "Session active. Expires in 14 minutes."
```

### Scenario 3: Session Expiration

```bash
# Step 1: Login
localpass login
# Enter: TestPass123!

# Step 2: Wait 16 minutes (or modify system time)
sleep 960  # 16 minutes

# Step 3: Try to use a command
localpass list
# Expected: "Session expired. Please login again."
# Should prompt for password
```

### Scenario 4: Explicit Logout

```bash
# Step 1: Login
localpass login
# Enter: TestPass123!

# Step 2: Verify session active
localpass status
# Expected: "Session active. Expires in 14 minutes."

# Step 3: Logout
localpass logout
# Expected: "Session terminated successfully."

# Step 4: Try to use a command
localpass list
# Expected: Password prompt (session cleared)
```

### Scenario 5: Security - No Persistent Sessions

```bash
# Step 1: Login
localpass login
# Enter: TestPass123!

# Step 2: Kill the process (simulate crash)
pkill -9 localpass

# Step 3: Try to use a command
localpass list
# Expected: Password prompt (no session persistence across crashes)
```

### Scenario 6: Audit Log Verification

```bash
# Step 1: Clear audit log (if exists)
rm ~/.local/share/localpass/audit.log 2>/dev/null

# Step 2: Perform authentication actions
localpass login  # Success
# Enter: TestPass123!

localpass login  # Failure
# Enter: WrongPassword

localpass logout

# Step 3: Check audit log
cat ~/.local/share/localpass/audit.log | jq .
# Expected: JSON lines with LOGIN_SUCCESS, LOGIN_FAILURE, SESSION_TERMINATED events
```

## Security Verification

### Check Session File Permissions

```bash
# After login
localpass login
# Enter: TestPass123!

# Check file permissions (Linux/macOS)
ls -la ~/.local/share/localpass/session.enc
# Expected: -rw------- (0600 permissions)

# Verify file is encrypted
file ~/.local/share/localpass/session.enc
# Expected: "data" (binary encrypted file, not text)
```

### Memory Security Test

```bash
# Run with memory profiler
python -m pytest tests/integration/test_session_memory.py -v
# Expected: All tests pass, no sensitive data in memory dumps
```

## Performance Verification

### Session Validation Speed

```bash
# Time session validation
time localpass status
# Expected: < 50ms total execution time
```

### Batch Operations

```bash
# Login once
localpass login

# Run multiple commands without re-auth
for i in {1..10}; do
    time localpass list > /dev/null
done
# Expected: Each command < 100ms (no password prompts)
```

## Troubleshooting

### Session Not Persisting

1. Check session file exists:
```bash
ls -la ~/.local/share/localpass/session.enc
```

2. Check file permissions:
```bash
stat ~/.local/share/localpass/session.enc
```

3. Enable debug logging:
```bash
LOCALPASS_DEBUG=1 localpass status
```

### Session Expired Too Early

1. Check system time:
```bash
date
timedatectl status
```

2. Check session details:
```bash
LOCALPASS_DEBUG=1 localpass status
```

### Audit Log Not Created

1. Check directory exists:
```bash
ls -la ~/.local/share/localpass/
```

2. Check write permissions:
```bash
touch ~/.local/share/localpass/test.txt
```

## Automated Test Suite

Run the full test suite:

```bash
# Unit tests
pytest tests/unit/test_session.py -v

# Integration tests
pytest tests/integration/test_session_persistence.py -v

# Security tests
pytest tests/security/test_session_security.py -v

# Full suite with coverage
pytest tests/ -v --cov=src.services.session_service --cov=src.services.auth_service
```

## Expected Outcomes

✅ **All manual test scenarios pass**  
✅ **Session persists for exactly 15 minutes**  
✅ **Session extends on activity**  
✅ **No authentication required within session**  
✅ **Session file properly encrypted**  
✅ **Audit events logged correctly**  
✅ **Performance targets met (<10ms validation)**  
✅ **Security requirements satisfied**

## Cleanup

After testing:

```bash
# Remove test database
rm ~/.localpass/test.db

# Clear session
localpass logout

# Remove audit logs
rm ~/.local/share/localpass/audit.log
```

---

*Quickstart guide version 1.0*  
*Created: 2025-01-12*