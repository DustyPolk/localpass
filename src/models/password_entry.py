"""Password Entry data model.

Represents a stored password record with full metadata and encryption support.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


@dataclass
class PasswordEntry:
    """Password entry with encrypted storage support."""
    
    # Required fields
    service: str
    username: str
    encrypted_password: str
    
    # Auto-generated fields
    id: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Optional fields
    url: Optional[str] = None
    encrypted_notes: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate password entry after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate password entry fields according to contract."""
        # Service name validation
        if not self.service or not (1 <= len(self.service) <= 100):
            raise ValueError("Service name must be between 1 and 100 characters")
        
        # Username validation
        if not self.username or not (1 <= len(self.username) <= 255):
            raise ValueError("Username must be between 1 and 255 characters")
        
        # Encrypted password validation
        if not self.encrypted_password:
            raise ValueError("Encrypted password cannot be empty")
        
        # Validate encrypted password is proper JSON with required fields
        try:
            data = json.loads(self.encrypted_password)
            required_fields = {'nonce', 'ciphertext', 'tag'}
            if not all(field in data for field in required_fields):
                raise ValueError("Encrypted password missing required encryption fields")
        except json.JSONDecodeError:
            raise ValueError("Encrypted password must be valid JSON")
        
        # URL validation if provided
        if self.url and not (self.url.startswith('http://') or self.url.startswith('https://')):
            raise ValueError("URL must be a valid HTTP/HTTPS URL")
    
    def get_password_strength(self, decrypted_password: str) -> str:
        """Calculate password strength indicator.
        
        Args:
            decrypted_password: The plaintext password to analyze
            
        Returns:
            Strength indicator: "Weak", "Medium", or "Strong"
        """
        if len(decrypted_password) < 8:
            return "Weak"
        
        has_upper = any(c.isupper() for c in decrypted_password)
        has_lower = any(c.islower() for c in decrypted_password)
        has_digit = any(c.isdigit() for c in decrypted_password)
        has_special = any(not c.isalnum() for c in decrypted_password)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if len(decrypted_password) >= 12 and complexity_score >= 3:
            return "Strong"
        elif len(decrypted_password) >= 8 and complexity_score >= 2:
            return "Medium"
        else:
            return "Weak"
    
    def to_dict(self) -> dict:
        """Convert password entry to dictionary representation."""
        return {
            'id': self.id,
            'service': self.service,
            'username': self.username,
            'encrypted_password': self.encrypted_password,
            'url': self.url,
            'encrypted_notes': self.encrypted_notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'PasswordEntry':
        """Create password entry from dictionary representation.
        
        Args:
            data: Dictionary containing password entry data
            
        Returns:
            PasswordEntry instance
        """
        # Parse datetime fields
        created_at = datetime.fromisoformat(data['created_at'])
        updated_at = datetime.fromisoformat(data['updated_at'])
        
        return cls(
            id=data.get('id'),
            service=data['service'],
            username=data['username'],
            encrypted_password=data['encrypted_password'],
            url=data.get('url'),
            encrypted_notes=data.get('encrypted_notes'),
            created_at=created_at,
            updated_at=updated_at,
        )
    
    @classmethod
    def from_database_row(cls, row: tuple) -> 'PasswordEntry':
        """Create password entry from database row tuple.
        
        Args:
            row: Database row tuple (id, service, username, encrypted_password, 
                 url, encrypted_notes, created_at, updated_at)
                 
        Returns:
            PasswordEntry instance
        """
        return cls(
            id=row[0],
            service=row[1],
            username=row[2],
            encrypted_password=row[3],
            url=row[4],
            encrypted_notes=row[5],
            created_at=datetime.fromisoformat(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
        )
    
    def update_timestamp(self) -> None:
        """Update the updated_at timestamp to current time."""
        self.updated_at = datetime.now()
    
    def __str__(self) -> str:
        """String representation for debugging."""
        return f"PasswordEntry(id={self.id}, service='{self.service}', username='{self.username}')"