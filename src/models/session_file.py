"""SessionFile model for encrypted storage.

This model represents the structure of session data as stored in encrypted files.
"""
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Dict, Any


@dataclass
class SessionFile:
    """Model for session data as stored in encrypted files."""
    
    session_id: str
    username: str
    created_at: str  # ISO-8601 format
    last_activity_at: str  # ISO-8601 format
    expires_at: str  # ISO-8601 format
    encrypted_derived_key: str  # Base64-encoded encrypted derived key
    checksum: str  # SHA-256 hex digest
    
    def __post_init__(self) -> None:
        """Validate SessionFile after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate SessionFile fields."""
        # Validate session_id is UUID format
        import uuid
        try:
            uuid.UUID(self.session_id, version=4)
        except ValueError:
            raise ValueError("session_id must be a valid UUID4")
        
        # Validate username
        if not self.username or not self.username.strip():
            raise ValueError("username cannot be empty")
        
        # Validate ISO-8601 timestamps
        try:
            datetime.fromisoformat(self.created_at)
            datetime.fromisoformat(self.last_activity_at)
            datetime.fromisoformat(self.expires_at)
        except ValueError as e:
            raise ValueError(f"Invalid timestamp format: {e}")
        
        # Validate checksum format (64-char hex string)
        if not isinstance(self.checksum, str) or len(self.checksum) != 64:
            raise ValueError("checksum must be a 64-character hex string")
        
        try:
            int(self.checksum, 16)  # Verify it's valid hex
        except ValueError:
            raise ValueError("checksum must be valid hexadecimal")
    
    @classmethod
    def from_session(cls, session) -> 'SessionFile':
        """Create SessionFile from Session object."""
        # Import here to avoid circular imports
        import sys
        if 'src.models.session' in sys.modules:
            Session = sys.modules['src.models.session'].Session
        else:
            from src.models.session import Session
        
        if not isinstance(session, Session):
            raise TypeError("Expected Session object")
        
        # Convert timestamps to ISO-8601
        created_at = session.created_at.isoformat()
        last_activity_at = session.last_activity_at.isoformat()
        expires_at = session.expires_at.isoformat()
        
        # Encrypt the derived key for secure storage
        encrypted_derived_key = cls._encrypt_derived_key(session.derived_key, session.username)
        
        # Calculate checksum of the data (including encrypted key)
        data_to_hash = f"{session.id}{session.username}{created_at}{last_activity_at}{expires_at}{encrypted_derived_key}"
        checksum = hashlib.sha256(data_to_hash.encode()).hexdigest()
        
        return cls(
            session_id=session.id,
            username=session.username,
            created_at=created_at,
            last_activity_at=last_activity_at,
            expires_at=expires_at,
            encrypted_derived_key=encrypted_derived_key,
            checksum=checksum
        )
    
    def to_session(self) -> 'Session':
        """Convert SessionFile back to Session object."""
        # Import here to avoid circular imports
        import sys
        if 'src.models.session' in sys.modules:
            Session = sys.modules['src.models.session'].Session
        else:
            from src.models.session import Session
        
        # Verify checksum
        data_to_hash = f"{self.session_id}{self.username}{self.created_at}{self.last_activity_at}{self.expires_at}{self.encrypted_derived_key}"
        expected_checksum = hashlib.sha256(data_to_hash.encode()).hexdigest()
        
        if self.checksum != expected_checksum:
            raise ValueError("Checksum mismatch - data may be corrupted")
        
        # Convert timestamps back to datetime
        created_at = datetime.fromisoformat(self.created_at)
        last_activity_at = datetime.fromisoformat(self.last_activity_at)
        
        # Decrypt the derived key
        derived_key = self._decrypt_derived_key(self.encrypted_derived_key, self.username)
        
        # Create Session object with restored derived_key
        session = Session(
            username=self.username,
            derived_key=derived_key,
            idle_timeout_minutes=15  # Default
        )
        
        # Override the auto-generated fields with stored values
        session.id = self.session_id
        session.created_at = created_at
        session.last_activity_at = last_activity_at
        
        return session
    
    @staticmethod
    def _encrypt_derived_key(derived_key: bytes, username: str) -> str:
        """Encrypt the derived key for secure storage.
        
        Args:
            derived_key: The database encryption key to encrypt
            username: Username for key derivation
            
        Returns:
            Base64-encoded encrypted key
        """
        if not derived_key:
            return ""  # Empty key
        
        import base64
        import getpass
        import platform
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Create session-specific encryption key from user/system info
        user_info = getpass.getuser()
        system_info = platform.node()
        
        # Create salt from consistent user/system info
        salt_data = f"session_key:{username}:{user_info}:{system_info}".encode()
        salt_hash = hashes.Hash(hashes.SHA256())
        salt_hash.update(salt_data)
        salt = salt_hash.finalize()[:16]  # 16 bytes for salt
        
        # Derive encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,  # Fewer iterations for session keys (performance)
        )
        
        # Use consistent password for session key derivation
        password = f"localpass_session:{username}:{user_info}".encode()
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # Encrypt the derived key
        fernet = Fernet(key)
        encrypted = fernet.encrypt(derived_key)
        
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def _decrypt_derived_key(encrypted_derived_key: str, username: str) -> bytes:
        """Decrypt the derived key from storage.
        
        Args:
            encrypted_derived_key: Base64-encoded encrypted key
            username: Username for key derivation
            
        Returns:
            Decrypted derived key bytes
        """
        if not encrypted_derived_key:
            return b""  # Empty key
        
        import base64
        import getpass
        import platform
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Create session-specific encryption key (same as encrypt)
        user_info = getpass.getuser()
        system_info = platform.node()
        
        # Create salt from consistent user/system info
        salt_data = f"session_key:{username}:{user_info}:{system_info}".encode()
        salt_hash = hashes.Hash(hashes.SHA256())
        salt_hash.update(salt_data)
        salt = salt_hash.finalize()[:16]  # 16 bytes for salt
        
        # Derive encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,  # Same as encrypt
        )
        
        # Use consistent password for session key derivation
        password = f"localpass_session:{username}:{user_info}".encode()
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # Decrypt the derived key
        fernet = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_derived_key.encode('utf-8'))
        decrypted = fernet.decrypt(encrypted_bytes)
        
        return decrypted
    
    def to_json(self) -> str:
        """Convert to JSON string for storage."""
        data = {
            'session_id': self.session_id,
            'username': self.username,
            'created_at': self.created_at,
            'last_activity_at': self.last_activity_at,
            'expires_at': self.expires_at,
            'encrypted_derived_key': self.encrypted_derived_key,
            'checksum': self.checksum
        }
        return json.dumps(data, separators=(',', ':'))  # Compact JSON
    
    @classmethod
    def from_json(cls, json_str: str) -> 'SessionFile':
        """Create SessionFile from JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        
        # Validate required fields
        required_fields = ['session_id', 'username', 'created_at', 'last_activity_at', 'expires_at', 'encrypted_derived_key', 'checksum']
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
        
        return cls(
            session_id=data['session_id'],
            username=data['username'],
            created_at=data['created_at'],
            last_activity_at=data['last_activity_at'],
            expires_at=data['expires_at'],
            encrypted_derived_key=data['encrypted_derived_key'],
            checksum=data['checksum']
        )
    
    def is_expired(self) -> bool:
        """Check if the stored session is expired."""
        expires_at = datetime.fromisoformat(self.expires_at)
        return datetime.now() > expires_at