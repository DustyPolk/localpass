"""Session data model.

Represents an authenticated user session with timeout management.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import uuid


@dataclass
class Session:
    """Authenticated user session with timeout management."""
    
    # Required fields
    username: str
    derived_key: bytes  # Database encryption key (memory only)
    
    # Auto-generated fields
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.now)
    last_activity_at: datetime = field(default_factory=datetime.now)
    
    # Configuration
    idle_timeout_minutes: int = 15
    max_session_hours: int = 4
    
    def __post_init__(self) -> None:
        """Validate session after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate session fields according to contract."""
        # Username validation
        if not self.username or len(self.username.strip()) == 0:
            raise ValueError("Username cannot be empty")
        
        # Session ID validation (UUID4 format)
        try:
            uuid.UUID(self.id, version=4)
        except ValueError:
            raise ValueError("Session ID must be a valid UUID4")
        
        # Derived key validation - allow empty bytes for loaded sessions
        if not isinstance(self.derived_key, (bytes, bytearray)):
            raise ValueError("Derived key must be bytes or bytearray")
        if len(self.derived_key) != 0 and len(self.derived_key) != 32:
            raise ValueError("Derived key must be exactly 32 bytes or empty")
        
        # Timeout validation
        if not (1 <= self.idle_timeout_minutes <= 120):
            raise ValueError("Idle timeout must be between 1 and 120 minutes")
        
        if not (1 <= self.max_session_hours <= 24):
            raise ValueError("Max session duration must be between 1 and 24 hours")
    
    @property
    def expires_at(self) -> datetime:
        """Calculate when session expires based on idle timeout.
        
        Returns:
            Datetime when session will expire due to inactivity
        """
        return self.last_activity_at + timedelta(minutes=self.idle_timeout_minutes)
    
    @property
    def max_expires_at(self) -> datetime:
        """Calculate maximum session expiration time.
        
        Returns:
            Datetime when session will expire regardless of activity
        """
        return self.created_at + timedelta(hours=self.max_session_hours)
    
    def is_active(self) -> bool:
        """Check if session is currently active and not expired.
        
        Returns:
            True if session is valid and not expired, False otherwise
        """
        now = datetime.now()
        
        # Check idle timeout
        if now > self.expires_at:
            return False
        
        # Check maximum session duration
        if now > self.max_expires_at:
            return False
        
        return True
    
    def update_activity(self) -> None:
        """Update last activity timestamp to current time."""
        self.last_activity_at = datetime.now()
    
    def get_remaining_time(self) -> timedelta:
        """Get remaining time before session expires.
        
        Returns:
            Timedelta representing remaining session time
        """
        if not self.is_active():
            return timedelta(0)
        
        now = datetime.now()
        idle_remaining = self.expires_at - now
        max_remaining = self.max_expires_at - now
        
        # Return whichever expires first
        return min(idle_remaining, max_remaining)
    
    def get_remaining_minutes(self) -> int:
        """Get remaining session time in minutes.
        
        Returns:
            Number of minutes remaining before session expires
        """
        remaining = self.get_remaining_time()
        return max(0, int(remaining.total_seconds() / 60))
    
    def to_dict(self, include_key: bool = False) -> dict:
        """Convert session to dictionary representation.
        
        Args:
            include_key: Whether to include the derived key (dangerous!)
            
        Returns:
            Dictionary representation of session
        """
        data = {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at.isoformat(),
            'last_activity_at': self.last_activity_at.isoformat(),
            'idle_timeout_minutes': self.idle_timeout_minutes,
            'max_session_hours': self.max_session_hours,
            'expires_at': self.expires_at.isoformat(),
            'max_expires_at': self.max_expires_at.isoformat(),
            'is_active': self.is_active(),
            'remaining_minutes': self.get_remaining_minutes(),
        }
        
        # Only include key if explicitly requested (for debugging)
        if include_key:
            data['derived_key'] = self.derived_key.hex()
        
        return data
    
    @classmethod
    def create_session(cls, username: str, derived_key: bytes, 
                      idle_timeout: int = 15, max_hours: int = 4) -> 'Session':
        """Create a new session with specified parameters.
        
        Args:
            username: Username for the session
            derived_key: Database encryption key (32 bytes)
            idle_timeout: Idle timeout in minutes
            max_hours: Maximum session duration in hours
            
        Returns:
            New Session instance
        """
        return cls(
            username=username,
            derived_key=derived_key,
            idle_timeout_minutes=idle_timeout,
            max_session_hours=max_hours
        )
    
    def zero_key(self) -> None:
        """Zero out the derived key for security (best effort in Python)."""
        if isinstance(self.derived_key, bytearray):
            for i in range(len(self.derived_key)):
                self.derived_key[i] = 0
        # Note: Can't fully zero immutable bytes, this is a Python limitation
    
    def __del__(self) -> None:
        """Attempt to zero key when session is destroyed."""
        try:
            self.zero_key()
        except:
            pass  # Best effort cleanup
    
    def __str__(self) -> str:
        """String representation for debugging."""
        return f"Session(id={self.id[:8]}..., user='{self.username}', active={self.is_active()})"