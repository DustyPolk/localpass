# Quick Start Guide: LocalPass Password Manager

**Feature**: 001-create-a-secure  
**Purpose**: User onboarding and basic workflow validation  
**Date**: 2025-09-11

## Prerequisites

- Python 3.13+ installed
- Terminal/command line access
- 50MB available disk space

## Installation

### From PyPI (Recommended)
```bash
pip install localpass
```

### From Source
```bash
git clone https://github.com/localpass/localpass.git
cd localpass
pip install -e .
```

### Verify Installation
```bash
localpass --version
# Expected: LocalPass 1.0.0
```

## Initial Setup (2 minutes)

### 1. Initialize Password Manager
```bash
localpass init
```

**Interactive Flow**:
```
Welcome to LocalPass!
This will create your secure password database.

Master password: [hidden input - enter secure password]
Confirm password: [hidden input - re-enter same password]

✓ Password manager initialized successfully
  Username: johndoe
  Database: ~/.local/share/localpass/passwords.db
```

**What this does**:
- Creates encrypted database file
- Stores master password hash securely
- Sets up directory structure

### 2. Authenticate (First Use)
```bash
localpass auth
```

**Interactive Flow**:
```
Master password: [hidden input]
✓ Authenticated successfully
  Session expires in 15 minutes
```

**What this does**:
- Verifies your master password
- Creates temporary session
- Enables password operations

## Basic Usage (5 minutes)

### Add Your First Password
```bash
localpass add gmail --username user@example.com
```

**Interactive Flow**:
```
Password for gmail: [hidden input - enter gmail password]
✓ Password for gmail added successfully
  Service: gmail
  Username: user@example.com
  Strength: Strong
```

### Generate and Add Secure Password
```bash
localpass add github --username myusername --generate
```

**Output**:
```
✓ Generated secure password for github
✓ Password for github added successfully
  Service: github
  Username: myusername
  Generated: K9mX#vQ2$nR7&pL4
  Strength: Strong
```

### View Your Passwords
```bash
localpass list
```

**Output**:
```
Password Manager Entries

┏━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ ID ┃ Service ┃ Username         ┃ Last Modified ┃ Strength ┃
┡━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ 1  │ gmail   │ user@example.com │ just now      │ ●        │
│ 2  │ github  │ myusername       │ just now      │ ●        │
└────┴─────────┴──────────────────┴───────────────┴──────────┘

Total entries: 2
```

### Retrieve a Password
```bash
localpass get gmail
```

**Output**:
```
Service: gmail
Username: user@example.com
Password: ************** (use --show to reveal)
Created: 2025-09-11 14:30:00
```

### Copy Password to Clipboard
```bash
localpass get gmail --copy
```

**Output**:
```
✓ Password copied to clipboard!
  Service: gmail
  Username: user@example.com
  Expires from clipboard in 30 seconds
```

## Advanced Usage (10 minutes)

### Search and Filter
```bash
# Find services matching pattern
localpass list --service "git*"

# Show recently updated entries
localpass list --recent 5
```

### Update Existing Password
```bash
# Update with new password
localpass update gmail

# Generate new password
localpass update github --generate --length 20
```

### Add Additional Information
```bash
localpass add aws-console \
  --username admin \
  --url "https://console.aws.amazon.com" \
  --notes "Production environment access"
```

### Export for Backup
```bash
# Export to encrypted JSON
localpass export --output backup.json

# Export to CSV for migration
localpass export --output backup.csv --format csv
```

## Scripting Integration (5 minutes)

### JSON Output Mode
All commands support `--format json` for scripting:

```bash
# Check if service exists
result=$(localpass get gmail --format json 2>/dev/null)
if [ $? -eq 0 ]; then
  echo "Gmail password found"
fi

# Get password for script usage
password=$(localpass get gmail --format json --show | jq -r '.password')
echo "Using password: $password"
```

### Automated Password Generation
```bash
#!/bin/bash
# Generate and store password for new service
SERVICE="$1"
USERNAME="$2"

if [ -z "$SERVICE" ] || [ -z "$USERNAME" ]; then
  echo "Usage: $0 <service> <username>"
  exit 1
fi

# Generate password and capture result
result=$(localpass add "$SERVICE" \
  --username "$USERNAME" \
  --generate \
  --format json)

# Extract generated password for immediate use
password=$(echo "$result" | jq -r '.generated_password')
echo "Created account for $SERVICE with password: $password"
```

### Batch Operations
```bash
#!/bin/bash
# Import from CSV file
while IFS=, read -r service username password url; do
  localpass add "$service" \
    --username "$username" \
    --password "$password" \
    --url "$url" \
    --format json
done < passwords.csv
```

## Security Best Practices

### Master Password Guidelines
- Use 16+ characters with mixed case, numbers, symbols
- Don't reuse your master password elsewhere
- Consider using a passphrase: "Coffee-Sunset-Mountain-92"

### Session Management
```bash
# Check session status
localpass auth --status

# Extend session (re-authenticate)
localpass auth

# Explicit logout (clear session)
localpass logout
```

### Regular Maintenance
```bash
# Weekly backup
localpass export --output "backup-$(date +%Y%m%d).json"

# Check database integrity
localpass verify

# Update weak passwords
localpass list --weak | xargs -I {} localpass update {} --generate
```

## Troubleshooting

### Common Issues

**"Authentication failed"**
```bash
# Check if you're using correct master password
localpass auth

# If forgotten, you'll need to reinitialize (loses all data)
localpass init --force
```

**"Session expired"**
```bash
# Re-authenticate
localpass auth
```

**"Database locked"**
```bash
# Check for other localpass processes
ps aux | grep localpass

# Kill any hanging processes
pkill localpass
```

### File Locations

**Configuration**: 
- Linux: `~/.config/localpass/`
- macOS: `~/Library/Application Support/LocalPass/`
- Windows: `%APPDATA%\LocalPass\`

**Database**:
- Linux: `~/.local/share/localpass/passwords.db`
- macOS: `~/Library/Application Support/LocalPass/passwords.db`
- Windows: `%APPDATA%\LocalPass\passwords.db`

### Environment Variables
```bash
export LOCALPASS_SESSION_TIMEOUT=30  # 30-minute sessions
export LOCALPASS_LOG_LEVEL=DEBUG     # Detailed logging
export LOCALPASS_DATA_DIR=/custom/path  # Custom data directory
```

## Next Steps

### Learn More
- Read the full documentation: `localpass --help`
- Security implementation details: `localpass security-info`
- Contributing: `localpass contribute-info`

### Advanced Features
- Set up shell integration for tab completion
- Configure backup automation
- Integrate with browser extensions (future release)

### Migration from Other Password Managers
```bash
# Import from 1Password CSV export
localpass import 1password-export.csv --format 1password

# Import from Bitwarden JSON export  
localpass import bitwarden-export.json --format bitwarden

# Import from KeePass CSV export
localpass import keepass-export.csv --format keepass
```

## Validation Checklist

This quickstart covers all core user scenarios:

- ✅ **FR-001**: Master password authentication (init, auth)
- ✅ **FR-002**: Add password entries (add command)
- ✅ **FR-003**: Retrieve stored passwords (get, list commands)
- ✅ **FR-004**: Update existing passwords (update command)
- ✅ **FR-005**: Delete password entries (delete command)
- ✅ **FR-008**: Clear visual feedback (Rich formatting)
- ✅ **FR-009**: Help text and usage (--help)
- ✅ **FR-010**: Scriptable output (--format json)
- ✅ **FR-014**: Password generation (--generate)
- ✅ **FR-016**: Search operations (list filtering)
- ✅ **FR-018**: Comprehensive documentation

Total time investment: ~20 minutes to full productivity

**Success Criteria**: User can store, retrieve, and manage passwords securely within 20 minutes of installation.