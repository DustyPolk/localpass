# CLI Interface Contract

**Feature**: 001-create-a-secure  
**Contract Type**: Command Line Interface  
**Date**: 2025-09-11

## Command Structure

All commands follow the pattern: `localpass <command> [arguments] [options]`

### Global Options
Available for all commands:

```bash
--format, -f {table|json}     Output format (default: table)
--quiet, -q                   Suppress non-essential output
--help                        Show command help
--version                     Show version information
```

## Authentication Commands

### `localpass init`
Initialize the password manager with a master password.

**Usage**: `localpass init [options]`

**Options**:
```bash
--username, -u TEXT          Master username (default: system username)
--force                      Overwrite existing master password
```

**Success Output** (table format):
```
✓ Password manager initialized successfully
  Username: johndoe
  Database: ~/.local/share/localpass/passwords.db
```

**Success Output** (json format):
```json
{
  "status": "success",
  "action": "init", 
  "username": "johndoe",
  "database_path": "~/.local/share/localpass/passwords.db"
}
```

**Error Cases**:
- Database already exists without --force
- Master password too weak
- Insufficient disk space

### `localpass auth`
Authenticate with master password (create session).

**Usage**: `localpass auth [options]`

**Options**:
```bash
--timeout INTEGER            Session timeout in minutes (default: 15)
```

**Interactive Flow**:
```
Master password: [hidden input]
✓ Authenticated successfully
  Session expires in 15 minutes
```

## CRUD Commands

### `localpass add`
Add a new password entry.

**Usage**: `localpass add SERVICE [options]`

**Arguments**:
- `SERVICE` (required): Service name (e.g., gmail, github)

**Options**:
```bash
--username, -u TEXT          Username for the service (required)
--password, -p TEXT          Password (if not provided, will prompt)
--generate, -g               Generate secure password
--length INTEGER             Generated password length (default: 16)
--url TEXT                   Service URL
--notes TEXT                 Additional notes
```

**Success Output** (table format):
```
✓ Password for gmail added successfully
  Service: gmail
  Username: user@example.com
  Strength: Strong
```

**Success Output** (json format):
```json
{
  "status": "success",
  "action": "add",
  "entry_id": 1,
  "service": "gmail",
  "username": "user@example.com",
  "password_strength": "Strong"
}
```

### `localpass get`
Retrieve password for a service.

**Usage**: `localpass get SERVICE [options]`

**Arguments**:
- `SERVICE` (required): Service name or pattern

**Options**:
```bash
--username, -u TEXT          Specific username (if multiple)
--show                       Show password in plain text
--copy, -c                   Copy password to clipboard
```

**Success Output** (table format, hidden):
```
Service: gmail
Username: user@example.com
Password: ************** (use --show to reveal)
Created: 2025-09-11 14:30:00
```

**Success Output** (table format, shown):
```
Service: gmail
Username: user@example.com  
Password: MySecureP@ssw0rd
Created: 2025-09-11 14:30:00
```

**Success Output** (json format):
```json
{
  "status": "success",
  "service": "gmail",
  "username": "user@example.com",
  "password": "MySecureP@ssw0rd",
  "url": "https://gmail.com",
  "created_at": "2025-09-11T14:30:00Z"
}
```

### `localpass list`
List password entries with optional filtering.

**Usage**: `localpass list [options]`

**Options**:
```bash
--service, -s PATTERN        Filter by service pattern
--recent INTEGER             Show N most recently updated
```

**Success Output** (table format):
```
Password Manager Entries

┏━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ ID ┃ Service ┃ Username         ┃ Last Modified ┃ Strength ┃
┡━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ 1  │ gmail   │ user@example.com │ 2 hours ago   │ ●        │
│ 2  │ github  │ username         │ 1 day ago     │ ●        │
│ 3  │ aws     │ admin            │ 3 days ago    │ ●        │
└────┴─────────┴──────────────────┴───────────────┴──────────┘

Total entries: 3
```

**Success Output** (json format):
```json
{
  "status": "success", 
  "count": 3,
  "entries": [
    {
      "id": 1,
      "service": "gmail",
      "username": "user@example.com",
      "last_modified": "2025-09-11T12:30:00Z",
      "password_strength": "Strong"
    }
  ]
}
```

### `localpass update`
Update an existing password entry.

**Usage**: `localpass update SERVICE [options]`

**Arguments**:
- `SERVICE` (required): Service name

**Options**:
```bash
--username, -u TEXT          Specific username (if multiple)
--password, -p TEXT          New password
--generate, -g               Generate new password  
--length INTEGER             Generated password length
--url TEXT                   Update service URL
--notes TEXT                 Update notes
```

**Success Output**:
```
✓ Password for gmail updated successfully
  Username: user@example.com
  Strength: Strong
```

### `localpass delete`
Delete a password entry.

**Usage**: `localpass delete SERVICE [options]`

**Arguments**:
- `SERVICE` (required): Service name

**Options**:
```bash
--username, -u TEXT          Specific username (if multiple)
--force                      Skip confirmation prompt
```

**Interactive Flow** (without --force):
```
Delete password entry for gmail (user@example.com)? [y/N]: y
✓ Password entry deleted successfully
```

## Utility Commands

### `localpass generate`
Generate a secure password without storing.

**Usage**: `localpass generate [options]`

**Options**:
```bash
--length INTEGER             Password length (default: 16)
--no-symbols                 Exclude special characters
--numbers-only              Numbers only
```

**Success Output**:
```json
{
  "status": "success",
  "password": "K9mX#vQ2$nR7&pL4",
  "length": 16,
  "strength": "Strong"
}
```

### `localpass export`
Export encrypted data for backup.

**Usage**: `localpass export [options]`

**Options**:
```bash
--output, -o PATH            Output file path
--format {json|csv}          Export format (default: json)
```

### `localpass import`
Import data from backup file.

**Usage**: `localpass import FILE [options]`

**Arguments**:
- `FILE` (required): Backup file path

**Options**:
```bash
--format {json|csv}          Input format (auto-detected)
--merge                      Merge with existing data
```

## Error Response Format

All commands return consistent error responses:

**Table Format**:
```
✗ Error message here
  Additional context if available
```

**JSON Format**:
```json
{
  "status": "error",
  "error_code": "AUTHENTICATION_FAILED",
  "message": "Invalid master password", 
  "details": {
    "attempts_remaining": 3
  }
}
```

## Common Error Codes

- `AUTHENTICATION_FAILED` - Invalid master password
- `SESSION_EXPIRED` - Session timed out, re-authentication required
- `ENTRY_NOT_FOUND` - Specified service/username not found
- `DUPLICATE_ENTRY` - Service/username combination already exists
- `VALIDATION_ERROR` - Invalid input parameters
- `DATABASE_ERROR` - Database access or corruption issue
- `PERMISSION_DENIED` - Insufficient file system permissions

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Authentication error
- `3` - Not found error
- `4` - Permission error
- `5` - Database error

## Environment Variables

- `LOCALPASS_CONFIG_DIR` - Override default config directory
- `LOCALPASS_DATA_DIR` - Override default data directory
- `LOCALPASS_SESSION_TIMEOUT` - Default session timeout in minutes
- `LOCALPASS_LOG_LEVEL` - Logging verbosity (DEBUG, INFO, WARNING, ERROR)

This contract ensures consistent behavior across all CLI operations and provides both human-friendly and machine-readable interfaces for all functionality.