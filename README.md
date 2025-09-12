# LocalPass =

**A secure, minimalist CLI password manager following Unix philosophy**

LocalPass is a production-ready password manager that prioritizes security, simplicity, and scriptability. Built with enterprise-grade cryptography and designed for both human users and automation scripts.

## ( Features

- = **Enterprise Security**: Argon2id password hashing, AES-256-GCM encryption, PBKDF2 key derivation
- <¨ **Beautiful CLI**: Rich formatting with tables and panels for human-readable output
- > **JSON API**: Machine-readable output for scripting and automation
- = **Password Generation**: Secure password generator with customizable parameters
- =á **Account Protection**: Automatic lockout after failed attempts, session timeouts
- < **Cross-Platform**: Works on Linux, macOS, and Windows with secure file permissions
- =Ê **Password Analysis**: Strength assessment and security recommendations
- = **Search & Filter**: Find passwords quickly with pattern matching
- =Ë **Clipboard Integration**: Optional clipboard support for password copying

## =€ Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd localpass

# Install with uv (recommended)
uv sync

# Or install with pip
pip install -e .
```

### Initialize Your Password Manager

```bash
# Initialize with secure master password
uv run localpass init --username myuser

# Master password will be prompted securely
```

### Basic Usage

```bash
# Add a password
uv run localpass add github --username myuser --url https://github.com

# Generate a secure password
uv run localpass add gitlab --username myuser --generate --length 20

# Retrieve a password (hidden by default)
uv run localpass get github

# Show password in output
uv run localpass get github --show

# Copy to clipboard
uv run localpass get github --copy

# List all passwords
uv run localpass list-passwords

# Search passwords
uv run localpass search git

# Update a password
uv run localpass update github myuser --generate

# Delete a password
uv run localpass delete github myuser
```

## =Ö Complete CLI Reference

### `init` - Initialize Password Manager

Initialize a new password database with your master password.

```bash
uv run localpass init [OPTIONS]

Options:
  --username TEXT     Username for the password manager (default: system user)
  --force            Reinitialize existing database
  --format TEXT      Output format: table (default) or json
  --quiet           Suppress non-essential output
```

**Examples:**
```bash
# Basic initialization
uv run localpass init

# Initialize with custom username
uv run localpass init --username john.doe

# Initialize with JSON output for scripting
uv run localpass init --format json

# Force reinitialize existing database
uv run localpass init --force
```

### `auth` - Authenticate

Authenticate with your master password and check session status.

```bash
uv run localpass auth [OPTIONS]

Options:
  --timeout INTEGER  Session timeout in minutes (default: 15)
  --status          Check current session status
  --format TEXT     Output format: table (default) or json
  --quiet          Suppress non-essential output
```

**Examples:**
```bash
# Authenticate with default 15-minute session
uv run localpass auth

# Authenticate with custom timeout
uv run localpass auth --timeout 30

# Check current session status
uv run localpass auth --status
```

### `add` - Add Password Entry

Add a new password entry to your database.

```bash
uv run localpass add SERVICE [OPTIONS]

Arguments:
  SERVICE  Service name for the password entry

Options:
  --username, -u TEXT    Username for the service [required]
  --generate, -g         Generate secure password
  --length, -l INTEGER   Generated password length (default: 16)
  --url TEXT            Service URL
  --notes TEXT          Additional notes
  --format TEXT         Output format: table (default) or json
  --quiet              Suppress non-essential output
```

**Examples:**
```bash
# Add password with manual entry
uv run localpass add facebook --username john@email.com --url https://facebook.com

# Generate secure password
uv run localpass add aws --username john@email.com --generate --length 24

# Add with notes
uv run localpass add database --username admin --notes "Production database credentials"

# JSON output for scripting
uv run localpass add redis --username admin --generate --format json
```

### `get` - Retrieve Password

Retrieve password entries for a service.

```bash
uv run localpass get SERVICE [OPTIONS]

Arguments:
  SERVICE  Service name to retrieve

Options:
  --username, -u TEXT  Specific username (optional)
  --copy, -c          Copy password to clipboard
  --show, -s          Show password in output
  --format TEXT       Output format: table (default) or json
  --quiet            Suppress non-essential output
```

**Examples:**
```bash
# Get password (hidden by default)
uv run localpass get github

# Show password in output
uv run localpass get github --show

# Copy to clipboard
uv run localpass get github --copy

# Get specific username if multiple exist
uv run localpass get github --username work@email.com

# JSON output with password visible
uv run localpass get github --show --format json
```

### `list-passwords` - List All Passwords

List password entries with filtering options.

```bash
uv run localpass list-passwords [OPTIONS]

Options:
  --service, -s TEXT   Service name pattern (supports wildcards)
  --limit, -l INTEGER  Maximum entries to show (default: 50)
  --format TEXT        Output format: table (default) or json
  --quiet             Suppress non-essential output
```

**Examples:**
```bash
# List all passwords
uv run localpass list-passwords

# List with service filter
uv run localpass list-passwords --service "git*"

# Limit results
uv run localpass list-passwords --limit 10

# JSON output for processing
uv run localpass list-passwords --format json | jq '.entries[].service'
```

### `search` - Search Passwords

Search password entries by service name or username.

```bash
uv run localpass search TERM [OPTIONS]

Arguments:
  TERM  Search term for service name or username

Options:
  --limit, -l INTEGER  Maximum results to show (default: 25)
  --format TEXT        Output format: table (default) or json
  --quiet             Suppress non-essential output
```

**Examples:**
```bash
# Search by service name
uv run localpass search github

# Search by username
uv run localpass search john@email.com

# Search with wildcards
uv run localpass search "git*"

# JSON output
uv run localpass search dev --format json
```

### `update` - Update Password Entry

Update an existing password entry.

```bash
uv run localpass update SERVICE USERNAME [OPTIONS]

Arguments:
  SERVICE   Service name to update
  USERNAME  Username to update

Options:
  --password, -p TEXT  New password (prompt if not provided)
  --url TEXT          New URL
  --notes TEXT        New notes
  --generate, -g      Generate new secure password
  --length, -l INT    Generated password length (default: 16)
  --format TEXT       Output format: table (default) or json
  --quiet            Suppress non-essential output
```

**Examples:**
```bash
# Update password (will prompt)
uv run localpass update github john@email.com

# Generate new password
uv run localpass update github john@email.com --generate --length 20

# Update URL and notes
uv run localpass update github john@email.com --url https://github.com/enterprise --notes "Work account"

# Update with inline password
uv run localpass update github john@email.com --password "newpassword123"
```

### `delete` - Delete Password Entry

Delete a password entry from the database.

```bash
uv run localpass delete SERVICE USERNAME [OPTIONS]

Arguments:
  SERVICE   Service name to delete
  USERNAME  Username to delete

Options:
  --force    Skip confirmation prompt
  --format TEXT  Output format: table (default) or json
  --quiet       Suppress non-essential output
```

**Examples:**
```bash
# Delete with confirmation
uv run localpass delete oldservice john@email.com

# Force delete without confirmation
uv run localpass delete oldservice john@email.com --force

# JSON output
uv run localpass delete oldservice john@email.com --format json
```

### `version` - Show Version

Display LocalPass version information.

```bash
uv run localpass version
```

## = Security Architecture

### Cryptographic Standards

LocalPass implements multiple layers of security using industry-standard algorithms:

#### Master Password Protection
- **Argon2id**: Memory-hard password hashing with 100MB memory cost
- **Parameters**: 8 iterations, 8-way parallelism, 100MB memory
- **Salt**: 32-byte random salt per user
- **Output**: 64-byte hash for authentication

#### Data Encryption
- **AES-256-GCM**: Authenticated encryption for password storage
- **Unique Nonces**: 96-bit random nonce per encryption operation
- **Authentication**: Built-in integrity verification via GCM tags
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations

#### Key Management
- **HKDF**: RFC 5869 key derivation for multiple keys from master key
- **Key Separation**: Separate keys for different data types
- **Memory Security**: Sensitive data cleared from memory after use
- **Zero-Knowledge**: Master password never stored, only verified

### File Security

#### Database Protection
- **File Permissions**: 600 (owner read/write only) on Unix systems
- **Directory Permissions**: 700 (owner access only)
- **Location**: Platform-specific secure directories
  - Linux: `~/.local/share/localpass/`
  - macOS: `~/Library/Application Support/LocalPass/`
  - Windows: `%APPDATA%\\LocalPass\\`

#### Cross-Platform Security
- **Windows**: Uses DPAPI for additional protection
- **macOS**: Follows macOS keychain patterns
- **Linux**: XDG Base Directory specification

### Session Management

#### Authentication Sessions
- **Timeout**: Configurable session timeouts (default: 15 minutes)
- **Idle Detection**: Sessions expire based on inactivity
- **Memory-Only**: Sessions not persisted between CLI invocations
- **Secure Cleanup**: Session data zeroed on timeout/exit

#### Account Protection
- **Failed Attempts**: Account lockout after 5 failed attempts
- **Lockout Duration**: Progressive lockout periods
- **Timing Attack Protection**: Consistent timing for authentication
- **Audit Trail**: Failed attempts logged securely

### Threat Model

LocalPass protects against:

 **Password Database Theft**: Strong encryption renders stolen database useless
 **Brute Force Attacks**: Argon2id makes password cracking computationally expensive
 **Memory Dumps**: Sensitive data cleared from memory after use
 **Timing Attacks**: Consistent operation timing prevents information leakage
 **Replay Attacks**: Unique nonces prevent ciphertext reuse
 **Privilege Escalation**: Secure file permissions limit access
 **Data Integrity**: GCM authentication prevents tampering

## =à Development

### Project Structure

```
localpass/
   src/
      cli/           # Command-line interface
      models/        # Data models
      services/      # Business logic services
      utils/         # Utility functions
   tests/
      contract/      # Contract/integration tests
      integration/   # End-to-end tests
   specs/             # Feature specifications
   scripts/           # Development scripts
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run specific test categories
uv run pytest tests/contract/
uv run pytest tests/integration/

# Run with coverage
uv run pytest --cov=src
```

### Development Workflow

```bash
# Create new feature branch
./scripts/create-new-feature.sh "feature description"

# Setup implementation plan
./scripts/setup-plan.sh

# Check prerequisites
./scripts/check-task-prerequisites.sh

# Development and testing...

# Merge to master when complete
```

## =' Configuration

### Environment Variables

- `LOCALPASS_DATA_DIR`: Override default data directory
- `LOCALPASS_DATABASE_PATH`: Override database file path
- `LOCALPASS_SESSION_TIMEOUT`: Default session timeout in minutes

### Configuration Examples

```bash
# Custom data directory
export LOCALPASS_DATA_DIR=/secure/location
uv run localpass init

# Custom database path
export LOCALPASS_DATABASE_PATH=/path/to/passwords.db
uv run localpass init

# Custom session timeout
export LOCALPASS_SESSION_TIMEOUT=30
uv run localpass auth
```

## > Scripting and Automation

### JSON API Examples

LocalPass provides machine-readable JSON output for all operations:

```bash
# Initialize and capture database path
INIT_RESULT=$(echo -e "password\\npassword" | uv run localpass init --format json)
DB_PATH=$(echo "$INIT_RESULT" | jq -r '.database_path')

# Add multiple passwords from a script
while IFS=',' read -r service username password url; do
    echo -e "masterpass\\n$password" | uv run localpass add "$service" \
        --username "$username" --url "$url" --format json
done < passwords.csv

# Export all passwords
uv run localpass auth --format json > /dev/null
PASSWORDS=$(echo "masterpass" | uv run localpass list-passwords --format json)
echo "$PASSWORDS" | jq '.entries[] | {service, username, url}'

# Backup database
cp "$DB_PATH" "backup-$(date +%Y%m%d).db"
```

### Integration Examples

#### Shell Function for Quick Access
```bash
# Add to ~/.bashrc or ~/.zshrc
lp() {
    case "$1" in
        get)
            echo "master_password" | uv run localpass get "$2" --show --quiet
            ;;
        add)
            uv run localpass add "$2" --username "$3" --generate
            ;;
        list)
            uv run localpass list-passwords --format json | jq -r '.entries[].service'
            ;;
        *)
            uv run localpass "$@"
            ;;
    esac
}
```

#### Password Rotation Script
```bash
#!/bin/bash
# rotate-passwords.sh - Rotate passwords for specified services

SERVICES=("github" "gitlab" "aws")
MASTER_PASSWORD="your_master_password"

for service in "${SERVICES[@]}"; do
    echo "Rotating password for $service..."
    
    # Generate new password
    result=$(echo "$MASTER_PASSWORD" | uv run localpass update "$service" myuser \
        --generate --length 24 --format json)
    
    if echo "$result" | jq -e '.status == "success"' > /dev/null; then
        echo " $service password rotated successfully"
    else
        echo " Failed to rotate $service password"
    fi
done
```

## = Troubleshooting

### Common Issues

#### Database Initialization

**Problem**: "Permission denied" when initializing database
```
Solution: Ensure the data directory is writable:
mkdir -p ~/.local/share/localpass
chmod 700 ~/.local/share/localpass
```

**Problem**: "Database already exists" error
```
Solution: Use --force flag to reinitialize:
uv run localpass init --force
```

#### Authentication Issues

**Problem**: "Invalid master password" despite correct password
```
Solution: Check for database corruption or recreate:
uv run localpass init --force
```

**Problem**: Account locked after failed attempts
```
Solution: Wait for lockout period to expire or reinitialize database
```

#### CLI Issues

**Problem**: "Command not found: localpass"
```
Solution: Use full command or install globally:
uv run localpass <command>
# or
pip install -e .
```

**Problem**: Clipboard functionality not working
```
Solution: Install clipboard support:
pip install pyperclip
# or on Linux:
sudo apt-get install xclip  # or xsel
```

### Performance Issues

**Problem**: Slow authentication/encryption operations
```
This is expected! Security parameters are intentionally expensive:
- Argon2id: 100MB memory, ~1-2 seconds on modern hardware
- PBKDF2: 600,000 iterations, ~0.5 seconds
- These delays prevent brute force attacks
```

### Debug Mode

Enable verbose output for troubleshooting:

```bash
# Add debug logging (if implemented)
LOCALPASS_DEBUG=1 uv run localpass <command>

# Check file permissions
ls -la ~/.local/share/localpass/

# Verify database integrity
sqlite3 ~/.local/share/localpass/passwords.db ".schema"
```

## S FAQ

### General Questions

**Q: How secure is LocalPass compared to other password managers?**
A: LocalPass uses enterprise-grade cryptography (Argon2id, AES-256-GCM) with security parameters matching or exceeding commercial solutions. The zero-knowledge architecture ensures even database theft doesn't compromise your passwords.

**Q: Can I use LocalPass on multiple devices?**
A: LocalPass is designed as a local-first tool. For multi-device sync, you can manually copy the encrypted database file, but consider the security implications of cloud storage.

**Q: What happens if I forget my master password?**
A: There's no recovery mechanism by design. The zero-knowledge architecture means your master password cannot be recovered - you'll need to reinitialize and lose access to existing passwords.

### Technical Questions

**Q: Why does authentication take so long?**
A: The ~1-2 second delay is intentional security - Argon2id with 100MB memory cost makes brute force attacks computationally expensive.

**Q: Can I change the security parameters?**
A: Security parameters are hardcoded to ensure consistent protection. Modifying them would require code changes and database migration.

**Q: How does LocalPass compare to browser password managers?**
A: LocalPass offers stronger encryption, local storage, CLI accessibility, and scriptability, but requires more technical knowledge than browser managers.

### Usage Questions

**Q: Can I export my passwords to other managers?**
A: Use the JSON API to export data:
```bash
echo "masterpass" | uv run localpass list-passwords --format json > export.json
```

**Q: How do I backup my passwords?**
A: Copy the encrypted database file:
```bash
cp ~/.local/share/localpass/passwords.db backup-$(date +%Y%m%d).db
```

**Q: Can I run LocalPass in scripts without prompts?**
A: Yes, use JSON format and pipe passwords:
```bash
echo "masterpass" | uv run localpass get service --format json
```

## =Ä License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## > Contributing

1. Fork the repository
2. Create a feature branch (`./scripts/create-new-feature.sh "description"`)
3. Make your changes following the development workflow
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## =Þ Support

- **Issues**: Report bugs via GitHub Issues
- **Documentation**: This README and inline help (`--help`)
- **Security Issues**: Report privately via email

---

**LocalPass** - Simple. Secure. Scriptable. =