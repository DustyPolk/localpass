"""Session Service.

Handles authenticated user sessions with timeout management.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict
from src.models.session import Session


class SessionService:
    """Service for managing authenticated user sessions."""
    
    def __init__(self):
        """Initialize session service."""
        self.active_sessions: Dict[str, Session] = {}
        self.default_timeout = 15  # minutes
        self.max_session_hours = 4
    
    def create_session(self, username: str, derived_key: bytes, 
                      idle_timeout: int = None, max_hours: int = None) -> Session:
        """Create a new authenticated session.
        
        Args:
            username: Authenticated username
            derived_key: Database encryption key (32 bytes)
            idle_timeout: Session idle timeout in minutes
            max_hours: Maximum session duration in hours
            
        Returns:
            New Session instance
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        
        if not isinstance(derived_key, bytes) or len(derived_key) != 32:
            raise ValueError("Derived key must be exactly 32 bytes")
        
        # Use defaults if not specified
        timeout = idle_timeout or self.default_timeout
        max_hrs = max_hours or self.max_session_hours
        
        # Terminate any existing session for this user
        self._terminate_user_sessions(username)
        
        # Create new session
        session = Session.create_session(
            username=username,
            derived_key=derived_key,
            idle_timeout=timeout,
            max_hours=max_hrs
        )
        
        # Store in active sessions
        self.active_sessions[session.id] = session
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get active session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session if found and active, None otherwise
        """
        if not session_id or session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        # Check if session is still active
        if not session.is_active():
            # Remove expired session
            del self.active_sessions[session_id]
            return None
        
        return session
    
    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate session and update activity timestamp.
        
        Args:
            session_id: Session identifier to validate
            
        Returns:
            Valid session or None if expired/invalid
        """
        session = self.get_session(session_id)
        
        if session:
            # Update last activity time
            session.update_activity()
            
        return session
    
    def get_user_session(self, username: str) -> Optional[Session]:
        """Get active session for a specific user.
        
        Args:
            username: Username to find session for
            
        Returns:
            Active session for user, None if no active session
        """
        for session in list(self.active_sessions.values()):
            if session.username == username and session.is_active():
                return session
        
        return None
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a specific session.
        
        Args:
            session_id: Session identifier to terminate
            
        Returns:
            True if session was terminated, False if not found
        """
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            # Zero out the key for security
            session.zero_key()
            del self.active_sessions[session_id]
            return True
        
        return False
    
    def terminate_user_sessions(self, username: str) -> int:
        """Terminate all sessions for a specific user.
        
        Args:
            username: Username whose sessions to terminate
            
        Returns:
            Number of sessions terminated
        """
        return self._terminate_user_sessions(username)
    
    def _terminate_user_sessions(self, username: str) -> int:
        """Internal method to terminate user sessions."""
        terminated_count = 0
        
        # Find all sessions for this user
        sessions_to_remove = []
        for session_id, session in self.active_sessions.items():
            if session.username == username:
                sessions_to_remove.append(session_id)
        
        # Remove found sessions
        for session_id in sessions_to_remove:
            if self.terminate_session(session_id):
                terminated_count += 1
        
        return terminated_count
    
    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions from memory.
        
        Returns:
            Number of expired sessions removed
        """
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if not session.is_active():
                expired_sessions.append(session_id)
        
        # Remove expired sessions
        removed_count = 0
        for session_id in expired_sessions:
            if self.terminate_session(session_id):
                removed_count += 1
        
        return removed_count
    
    def get_session_info(self, session_id: str) -> Optional[dict]:
        """Get session information without exposing sensitive data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information dictionary or None
        """
        session = self.get_session(session_id)
        
        if not session:
            return None
        
        return {
            'id': session.id,
            'username': session.username,
            'created_at': session.created_at.isoformat(),
            'last_activity_at': session.last_activity_at.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'remaining_minutes': session.get_remaining_minutes(),
            'is_active': session.is_active(),
            'idle_timeout_minutes': session.idle_timeout_minutes,
            'max_session_hours': session.max_session_hours
        }
    
    def get_all_sessions_info(self) -> list:
        """Get information about all active sessions.
        
        Returns:
            List of session information dictionaries
        """
        sessions_info = []
        
        for session_id in list(self.active_sessions.keys()):
            session_info = self.get_session_info(session_id)
            if session_info:  # Only include active sessions
                sessions_info.append(session_info)
        
        return sessions_info
    
    def extend_session(self, session_id: str, additional_minutes: int = None) -> bool:
        """Extend session timeout.
        
        Args:
            session_id: Session to extend
            additional_minutes: Additional minutes to add (default: reset to full timeout)
            
        Returns:
            True if session was extended, False if not found or expired
        """
        session = self.get_session(session_id)
        
        if not session:
            return False
        
        if additional_minutes:
            # Add specific time
            session.last_activity_at = session.last_activity_at + timedelta(minutes=additional_minutes)
        else:
            # Reset to current time (full timeout period)
            session.update_activity()
        
        return True
    
    def get_stats(self) -> dict:
        """Get session service statistics.
        
        Returns:
            Dictionary with session statistics
        """
        total_sessions = len(self.active_sessions)
        active_sessions = len([s for s in self.active_sessions.values() if s.is_active()])
        expired_sessions = total_sessions - active_sessions
        
        users = set(s.username for s in self.active_sessions.values() if s.is_active())
        
        return {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'unique_users': len(users),
            'default_timeout_minutes': self.default_timeout,
            'max_session_hours': self.max_session_hours
        }
    
    def clear_all_sessions(self) -> int:
        """Clear all sessions (for shutdown or security purposes).
        
        Returns:
            Number of sessions cleared
        """
        count = len(self.active_sessions)
        
        # Zero out all keys for security
        for session in self.active_sessions.values():
            session.zero_key()
        
        # Clear all sessions
        self.active_sessions.clear()
        
        return count