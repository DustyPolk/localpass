"""Session configuration constants for LocalPass.

This module defines all session-related configuration values including
timeouts, file paths, and security parameters.
"""

# Session timeout configuration
SESSION_IDLE_TIMEOUT_MINUTES = 15  # Fixed 15-minute idle timeout as per spec
MAX_SESSION_DURATION_HOURS = 4     # Maximum session duration regardless of activity

# Session file configuration
SESSION_FILE_NAME = "session.enc"
SESSION_FILE_PERMISSIONS = 0o600  # Owner read/write only

# Audit log configuration
AUDIT_LOG_FILE_NAME = "audit.log"
AUDIT_LOG_RETENTION_DAYS = 90
AUDIT_LOG_MAX_SIZE_MB = 100

# Security configuration
SESSION_ENCRYPTION_ALGORITHM = "AES-256-GCM"
SESSION_KEY_DERIVATION_ITERATIONS = 100000  # PBKDF2 iterations
SESSION_NONCE_SIZE = 12  # AES-GCM nonce size in bytes
SESSION_TAG_SIZE = 16    # AES-GCM authentication tag size in bytes

# Memory security
SECURE_MEMORY_WIPE_PASSES = 3  # Number of passes to overwrite memory

# Application name for platform-specific paths
APP_NAME = "localpass"
APP_AUTHOR = "LocalPass"  # Used for Windows paths