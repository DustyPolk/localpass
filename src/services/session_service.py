"""Session Service.

Handles authenticated user sessions with timeout management and persistence.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict
from src.models.session import Session
from src.services.storage.session_storage_service import SessionStorageService
from src.services.audit_service import AuditService
from src.services.memory_security_service import MemorySecurityService


class SessionService:
    """Service for managing authenticated user sessions."""
    
    def __init__(self, storage_service: Optional[SessionStorageService] = None,
                 audit_service: Optional[AuditService] = None,
                 memory_service: Optional[MemorySecurityService] = None):
        """Initialize session service."""
        self.active_sessions: Dict[str, Session] = {}
        self.default_timeout = 15  # minutes
        self.max_session_hours = 4
        
        # Initialize services
        self.storage_service = storage_service or SessionStorageService()
        self.audit_service = audit_service or AuditService()
        self.memory_service = memory_service or MemorySecurityService()
    
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
    
    def persist_session(self, session: Session) -> bool:
        """Persist session to storage.
        
        Args:
            session: Session to persist
            
        Returns:
            True if persistence succeeded, False otherwise
        """
        try:
            result = self.storage_service.persist_session(session)
            
            # Log audit event
            self.audit_service.log_event(
                event_type="SESSION_PERSISTED",
                username=session.username,
                session_id=session.id,
                success=True,
                details={'file_path': result.get('file_path')}
            )
            
            return True
        except Exception:
            return False
    
    def load_existing_session(self) -> Optional[Session]:
        """Load existing session from storage.
        
        Returns:
            Session if found and valid, None otherwise
        """
        try:
            session = self.storage_service.load_session()
            
            if session and session.is_active():
                # Add to active sessions (but with empty key - needs to be set elsewhere)
                self.active_sessions[session.id] = session
                
                # Log audit event
                self.audit_service.log_event(
                    event_type="SESSION_LOADED",
                    username=session.username,
                    session_id=session.id,
                    success=True
                )
                
                return session
            
            return None
            
        except Exception:
            return None
    
    def extend_session(self, session_id: str) -> Optional[Session]:
        """Extend session timeout (rolling timeout).
        
        Args:
            session_id: Session ID to extend
            
        Returns:
            Extended session or None if not found/expired
        """
        session = self.get_session(session_id)
        
        if not session:
            # Try to load from storage
            stored_session = self.load_existing_session()
            if stored_session and stored_session.id == session_id:
                session = stored_session
            else:
                return None
        
        if not session.is_active():
            # Session expired, log event
            self.audit_service.log_event(
                event_type="SESSION_EXPIRED",
                username=session.username,
                session_id=session_id,
                success=False,
                details={'reason': 'timeout_expired'}
            )
            
            # Clean up expired session
            self._cleanup_session(session)
            return None
        
        # Update activity time
        session.update_activity()
        
        # Persist the updated session
        self.persist_session(session)
        
        # Log extension event
        self.audit_service.log_event(
            event_type="SESSION_EXTENDED",
            username=session.username,
            session_id=session_id,
            success=True
        )
        
        return session
    
    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate session and update activity timestamp.
        
        Args:
            session_id: Session identifier to validate
            
        Returns:
            Valid session or None if expired/invalid
        """
        # First check in-memory sessions
        session = self.get_session(session_id)
        
        # If not in memory, try to load from storage
        if not session:
            session = self.load_existing_session()
            if session and session.id != session_id:
                session = None
        
        if not session:
            return None
        
        # Check if still active
        if not session.is_active():
            # Session expired
            self.audit_service.log_event(
                event_type="SESSION_EXPIRED",
                username=session.username,
                session_id=session_id,
                success=False
            )
            
            # Clean up
            self._cleanup_session(session)
            return None
        
        # Update activity and persist
        session.update_activity()
        self.persist_session(session)
        
        # Log validation event
        self.audit_service.log_event(
            event_type="SESSION_VALIDATED",
            username=session.username,
            session_id=session_id,
            success=True
        )
        
        return session
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate session and clean up.
        
        Args:
            session_id: Session ID to terminate
            
        Returns:
            True if session was terminated, False if not found
        """
        session = self.get_session(session_id)
        
        # Also try to load from storage if not in memory
        if not session:
            stored_session = self.load_existing_session()
            if stored_session and stored_session.id == session_id:
                session = stored_session
        
        if not session:
            return False
        
        # Log termination event
        self.audit_service.log_event(
            event_type="SESSION_TERMINATED",
            username=session.username,
            session_id=session_id,
            success=True,
            details={'reason': 'manual_logout'}
        )
        
        # Clean up session
        self._cleanup_session(session)
        
        return True
    
    def get_current_session(self) -> Optional[Session]:
        """Get the current active session (if any).
        
        Returns:
            Current session or None if no active session exists
        """
        # Try to load from storage first
        session = self.load_existing_session()
        
        if session and session.is_active():
            return session
        
        return None
    
    def _cleanup_session(self, session: Session) -> None:
        """Clean up session resources.
        
        Args:
            session: Session to clean up
        """
        # Remove from active sessions
        if session.id in self.active_sessions:
            del self.active_sessions[session.id]
        
        # Clear sensitive memory
        if isinstance(session.derived_key, bytearray):
            self.memory_service.secure_clear(session.derived_key)
        else:
            # Try to zero the key
            session.zero_key()
        
        # Delete persisted session
        try:
            self.storage_service.delete_session()
        except Exception:
            pass  # Best effort cleanup