"""Key Derivation Service.

Handles key derivation from master password using PBKDF2 and HKDF.
Implements the security interface contract for key derivation operations.
"""
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class KeyDerivationService:
    """Service for key derivation operations."""

    def __init__(self):
        """Initialize key derivation service."""
        # High iteration count for 2025 OWASP standards
        self.pbkdf2_iterations = 600000
        self.default_key_length = 32  # AES-256 key size
        
    def derive_database_key(self, master_password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive database encryption key from master password.
        
        Args:
            master_password: Master password (8-128 characters)
            salt: Optional salt (if None, generates new 32-byte salt)
            
        Returns:
            Tuple of (key: bytes, salt: bytes) where key is 32 bytes for AES-256
            
        Raises:
            ValueError: If password or salt parameters are invalid
            SystemError: If key derivation fails
        """
        # Validate master password
        if not isinstance(master_password, str):
            raise ValueError("Master password must be a string")
        
        if not (8 <= len(master_password) <= 128):
            raise ValueError("Master password must be between 8 and 128 characters")
        
        # Generate salt if not provided
        if salt is None:
            salt = secrets.token_bytes(32)
        elif not isinstance(salt, bytes) or len(salt) != 32:
            raise ValueError("Salt must be exactly 32 bytes")
        
        try:
            # Set up PBKDF2-HMAC-SHA256
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.default_key_length,
                salt=salt,
                iterations=self.pbkdf2_iterations,
                backend=default_backend()
            )
            
            # Derive key from password
            password_bytes = master_password.encode('utf-8')
            derived_key = kdf.derive(password_bytes)
            
            # Verify key length
            if len(derived_key) != self.default_key_length:
                raise SystemError(f"Derived key has wrong length: {len(derived_key)}")
                
            return derived_key, salt
            
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise SystemError(f"Key derivation failed: {e}")
    
    def derive_session_key(self, master_key: bytes, context: bytes) -> bytes:
        """Derive session-specific key from master key using HKDF.
        
        Args:
            master_key: 32-byte master key material
            context: Context string for key separation
            
        Returns:
            32-byte derived session key
            
        Raises:
            ValueError: If master key or context parameters are invalid
            SystemError: If key derivation fails
        """
        # Validate master key
        if not isinstance(master_key, bytes) or len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes")
        
        # Validate context
        if not isinstance(context, bytes):
            raise ValueError("Context must be bytes")
        
        try:
            # Set up HKDF-SHA256
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=self.default_key_length,
                salt=None,  # HKDF can work without salt when input is already high-entropy
                info=context,
                backend=default_backend()
            )
            
            # Derive session key
            session_key = hkdf.derive(master_key)
            
            # Verify key length
            if len(session_key) != self.default_key_length:
                raise SystemError(f"Session key has wrong length: {len(session_key)}")
                
            return session_key
            
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise SystemError(f"Session key derivation failed: {e}")
    
    def derive_multiple_keys(self, master_key: bytes) -> dict:
        """Derive multiple keys from strong master key material.
        
        Args:
            master_key: 32-byte high-entropy key material
            
        Returns:
            Dictionary with derived keys for different purposes
            
        Raises:
            ValueError: If master key is invalid
            SystemError: If any key derivation fails
        """
        if not isinstance(master_key, bytes) or len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes")
        
        keys = {}
        
        try:
            # Database encryption key
            keys['database'] = self.derive_session_key(master_key, b'database-encryption')
            
            # Session token signing key  
            keys['session'] = self.derive_session_key(master_key, b'session-signing')
            
            # Backup encryption key
            keys['backup'] = self.derive_session_key(master_key, b'backup-encryption')
            
            # File encryption key
            keys['file'] = self.derive_session_key(master_key, b'file-encryption')
            
            return keys
            
        except Exception as e:
            raise SystemError(f"Multiple key derivation failed: {e}")
    
    def verify_key_derivation(self, password: str, salt: bytes, expected_key: bytes) -> bool:
        """Verify that a password produces the expected derived key.
        
        Args:
            password: Master password to test
            salt: Salt used in original derivation  
            expected_key: Expected derived key
            
        Returns:
            True if password produces expected key, False otherwise
        """
        try:
            derived_key, _ = self.derive_database_key(password, salt)
            
            # Use constant-time comparison for security
            import hmac
            return hmac.compare_digest(derived_key, expected_key)
            
        except:
            return False
    
    def get_key_info(self) -> dict:
        """Get information about current key derivation parameters.
        
        Returns:
            Dictionary containing key derivation configuration
        """
        return {
            'pbkdf2_algorithm': 'PBKDF2-HMAC-SHA256',
            'pbkdf2_iterations': self.pbkdf2_iterations,
            'hkdf_algorithm': 'HKDF-SHA256',
            'default_key_length': self.default_key_length,
            'salt_length': 32,
            'supported_contexts': [
                'database-encryption',
                'session-signing', 
                'backup-encryption',
                'file-encryption'
            ]
        }
    
    def generate_salt(self, length: int = 32) -> bytes:
        """Generate cryptographically secure random salt.
        
        Args:
            length: Salt length in bytes (default: 32)
            
        Returns:
            Cryptographically secure random bytes
            
        Raises:
            ValueError: If length is invalid
        """
        if not isinstance(length, int) or length <= 0 or length > 1024:
            raise ValueError("Salt length must be between 1 and 1024 bytes")
        
        return secrets.token_bytes(length)