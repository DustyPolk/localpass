"""AuthEvent model for audit logging.

This model represents authentication and session events for security auditing.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
import uuid
import json


class EventType(Enum):
    """Enumeration of audit event types."""
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_EXTENDED = "SESSION_EXTENDED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_TERMINATED = "SESSION_TERMINATED"
    SESSION_VALIDATED = "SESSION_VALIDATED"
    SESSION_INVALID = "SESSION_INVALID"
    SESSION_PERSISTED = "SESSION_PERSISTED"
    SESSION_LOADED = "SESSION_LOADED"


@dataclass
class AuthEvent:
    """Model for audit log events."""
    
    # Required fields
    event_type: str
    username: str
    success: bool
    
    # Auto-generated fields
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Optional fields
    session_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Validate AuthEvent after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate AuthEvent fields."""
        # Validate event_id is UUID format
        try:
            uuid.UUID(self.id, version=4)
        except ValueError:
            raise ValueError("id must be a valid UUID4")
        
        # Validate event_type
        valid_types = [e.value for e in EventType]
        if self.event_type not in valid_types:
            raise ValueError(f"Invalid event type: {self.event_type}. Valid types: {valid_types}")
        
        # Validate username
        if not self.username or not self.username.strip():
            raise ValueError("username cannot be empty")
        
        # Validate session_id if provided
        if self.session_id is not None:
            try:
                uuid.UUID(self.session_id, version=4)
            except ValueError:
                raise ValueError("session_id must be a valid UUID4 or None")
        
        # Validate success is boolean
        if not isinstance(self.success, bool):
            raise ValueError("success must be a boolean")
        
        # Validate details is a dict
        if not isinstance(self.details, dict):
            raise ValueError("details must be a dictionary")
        
        # Validate timestamp
        if not isinstance(self.timestamp, datetime):
            raise ValueError("timestamp must be a datetime object")
    
    def to_json_line(self) -> str:
        """Convert to JSON Lines format for logging."""
        data = {
            'id': self.id,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'username': self.username,
            'success': self.success,
            'session_id': self.session_id,
            'details': self.details
        }
        return json.dumps(data, separators=(',', ':'))  # Compact JSON
    
    @classmethod
    def from_json_line(cls, json_line: str) -> 'AuthEvent':
        """Create AuthEvent from JSON Lines format."""
        try:
            data = json.loads(json_line.strip())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        
        # Parse timestamp
        timestamp = datetime.fromisoformat(data['timestamp'])
        
        return cls(
            id=data['id'],
            event_type=data['event_type'],
            timestamp=timestamp,
            username=data['username'],
            success=data['success'],
            session_id=data.get('session_id'),
            details=data.get('details', {})
        )
    
    @classmethod
    def create_login_attempt(cls, username: str) -> 'AuthEvent':
        """Create LOGIN_ATTEMPT event."""
        return cls(
            event_type=EventType.LOGIN_ATTEMPT.value,
            username=username,
            success=False,  # Attempt, not success yet
            details={}
        )
    
    @classmethod
    def create_login_success(cls, username: str, session_id: str, details: Dict[str, Any] = None) -> 'AuthEvent':
        """Create LOGIN_SUCCESS event."""
        return cls(
            event_type=EventType.LOGIN_SUCCESS.value,
            username=username,
            session_id=session_id,
            success=True,
            details=details or {}
        )
    
    @classmethod
    def create_login_failure(cls, username: str, reason: str, remaining_attempts: int = None) -> 'AuthEvent':
        """Create LOGIN_FAILURE event."""
        details = {'reason': reason}
        if remaining_attempts is not None:
            details['remaining_attempts'] = remaining_attempts
            
        return cls(
            event_type=EventType.LOGIN_FAILURE.value,
            username=username,
            success=False,
            details=details
        )
    
    @classmethod
    def create_session_created(cls, username: str, session_id: str) -> 'AuthEvent':
        """Create SESSION_CREATED event."""
        return cls(
            event_type=EventType.SESSION_CREATED.value,
            username=username,
            session_id=session_id,
            success=True,
            details={}
        )
    
    @classmethod
    def create_session_extended(cls, username: str, session_id: str) -> 'AuthEvent':
        """Create SESSION_EXTENDED event."""
        return cls(
            event_type=EventType.SESSION_EXTENDED.value,
            username=username,
            session_id=session_id,
            success=True,
            details={}
        )
    
    @classmethod
    def create_session_expired(cls, username: str, session_id: str, reason: str = "idle_timeout") -> 'AuthEvent':
        """Create SESSION_EXPIRED event."""
        return cls(
            event_type=EventType.SESSION_EXPIRED.value,
            username=username,
            session_id=session_id,
            success=False,
            details={'reason': reason}
        )
    
    @classmethod
    def create_session_terminated(cls, username: str, session_id: str, reason: str = "logout") -> 'AuthEvent':
        """Create SESSION_TERMINATED event."""
        return cls(
            event_type=EventType.SESSION_TERMINATED.value,
            username=username,
            session_id=session_id,
            success=True,
            details={'reason': reason}
        )
    
    @classmethod
    def create_session_validated(cls, username: str, session_id: str) -> 'AuthEvent':
        """Create SESSION_VALIDATED event."""
        return cls(
            event_type=EventType.SESSION_VALIDATED.value,
            username=username,
            session_id=session_id,
            success=True,
            details={}
        )
    
    @classmethod
    def create_session_invalid(cls, username: str, session_id: str, reason: str) -> 'AuthEvent':
        """Create SESSION_INVALID event."""
        return cls(
            event_type=EventType.SESSION_INVALID.value,
            username=username,
            session_id=session_id,
            success=False,
            details={'reason': reason}
        )