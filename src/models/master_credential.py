"""Master Credential data model.

Represents the user's master authentication and encryption key management.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


@dataclass
class MasterCredential:
    """Master credential for user authentication and key derivation."""
    
    # Required fields
    username: str
    password_hash: str
    salt: bytes
    key_derivation_params: dict
    
    # Auto-generated fields  
    id: int = 1  # Always 1 - single record
    created_at: datetime = field(default_factory=datetime.now)
    
    # Updated fields
    last_auth_at: Optional[datetime] = None
    auth_failure_count: int = 0
    locked_until: Optional[datetime] = None
    
    def __post_init__(self) -> None:
        """Validate master credential after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate master credential fields according to contract."""
        # ID validation - must always be 1
        if self.id != 1:
            raise ValueError("Master credential ID must be 1")
        
        # Username validation
        if not self.username or len(self.username.strip()) == 0:
            raise ValueError("Username cannot be empty")
        
        # Password hash validation
        if not self.password_hash or not self.password_hash.startswith('$argon2id$'):
            raise ValueError("Password hash must be valid Argon2id format")
        
        # Salt validation
        if not isinstance(self.salt, bytes) or len(self.salt) != 32:
            raise ValueError("Salt must be exactly 32 bytes")
        
        # Key derivation params validation
        if not isinstance(self.key_derivation_params, dict):
            raise ValueError("Key derivation params must be a dictionary")
        
        required_params = {'algorithm', 'iterations'}
        if not all(param in self.key_derivation_params for param in required_params):
            raise ValueError("Key derivation params missing required fields")
    
    def is_locked(self) -> bool:
        """Check if account is currently locked due to failed attempts.
        
        Returns:
            True if account is locked, False otherwise
        """
        if self.locked_until is None:
            return False
        
        return datetime.now() < self.locked_until
    
    def increment_failure_count(self) -> None:
        """Increment authentication failure count and lock if threshold reached."""
        self.auth_failure_count += 1
        
        # Lock account after 5 failed attempts for 15 minutes
        if self.auth_failure_count >= 5:
            self.locked_until = datetime.now().replace(microsecond=0) + \
                              datetime.timedelta(minutes=15)
    
    def reset_failure_count(self) -> None:
        """Reset authentication failure count after successful login."""
        self.auth_failure_count = 0
        self.locked_until = None
        self.last_auth_at = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert master credential to dictionary representation."""
        return {
            'id': self.id,
            'username': self.username,
            'password_hash': self.password_hash,
            'salt': self.salt.hex(),  # Convert bytes to hex string
            'key_derivation_params': json.dumps(self.key_derivation_params),
            'created_at': self.created_at.isoformat(),
            'last_auth_at': self.last_auth_at.isoformat() if self.last_auth_at else None,
            'auth_failure_count': self.auth_failure_count,
            'locked_until': self.locked_until.isoformat() if self.locked_until else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'MasterCredential':
        """Create master credential from dictionary representation.
        
        Args:
            data: Dictionary containing master credential data
            
        Returns:
            MasterCredential instance
        """
        # Parse datetime fields
        created_at = datetime.fromisoformat(data['created_at'])
        last_auth_at = datetime.fromisoformat(data['last_auth_at']) if data['last_auth_at'] else None
        locked_until = datetime.fromisoformat(data['locked_until']) if data['locked_until'] else None
        
        # Parse other fields
        salt = bytes.fromhex(data['salt'])
        key_derivation_params = json.loads(data['key_derivation_params'])
        
        return cls(
            id=data['id'],
            username=data['username'],
            password_hash=data['password_hash'],
            salt=salt,
            key_derivation_params=key_derivation_params,
            created_at=created_at,
            last_auth_at=last_auth_at,
            auth_failure_count=data['auth_failure_count'],
            locked_until=locked_until,
        )
    
    @classmethod
    def from_database_row(cls, row: tuple) -> 'MasterCredential':
        """Create master credential from database row tuple.
        
        Args:
            row: Database row tuple (id, username, password_hash, salt,
                 key_derivation_params, created_at, last_auth_at, 
                 auth_failure_count, locked_until)
                 
        Returns:
            MasterCredential instance
        """
        # Parse fields from row
        salt = row[3] if isinstance(row[3], bytes) else bytes.fromhex(row[3])
        key_derivation_params = json.loads(row[4]) if isinstance(row[4], str) else row[4]
        
        last_auth_at = datetime.fromisoformat(row[6]) if row[6] else None
        locked_until = datetime.fromisoformat(row[8]) if row[8] else None
        
        return cls(
            id=row[0],
            username=row[1], 
            password_hash=row[2],
            salt=salt,
            key_derivation_params=key_derivation_params,
            created_at=datetime.fromisoformat(row[5]),
            last_auth_at=last_auth_at,
            auth_failure_count=row[7],
            locked_until=locked_until,
        )
    
    def get_key_derivation_salt(self) -> bytes:
        """Get salt for key derivation operations.
        
        Returns:
            Salt bytes for PBKDF2 key derivation
        """
        return self.salt
    
    def __str__(self) -> str:
        """String representation for debugging."""
        return f"MasterCredential(username='{self.username}', failures={self.auth_failure_count})"