"""Contract test for POST /session/extend endpoint.

Tests the session extension API contract as defined in session-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import uuid


class TestSessionExtendContract:
    """Contract tests for session extension endpoint."""
    
    def test_extend_active_session(self):
        """Test extending an active session's timeout."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create an active session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        original_activity = test_session.last_activity_at
        original_expires = test_session.expires_at
        session_service.active_sessions[test_session.id] = test_session
        
        # Act
        extended_session = session_service.extend_session(test_session.id)
        
        # Assert - Contract requirements
        assert extended_session is not None
        assert extended_session.id == test_session.id
        assert extended_session.username == "testuser"
        
        # Verify activity timestamp updated
        assert extended_session.last_activity_at > original_activity
        
        # Verify expiration extended by 15 minutes from now
        new_expires = extended_session.last_activity_at + timedelta(minutes=15)
        assert abs((extended_session.expires_at - new_expires).total_seconds()) < 1
        
        # Verify it's actually extended (not same as before)
        assert extended_session.expires_at > original_expires
        
        # Verify remaining time is close to 15 minutes
        remaining = extended_session.get_remaining_time()
        assert 890 <= remaining.total_seconds() <= 900  # ~15 minutes
    
    def test_extend_expired_session_fails(self):
        """Test that expired sessions cannot be extended."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create an expired session
        expired_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        # Force expiration
        expired_session.last_activity_at = datetime.now() - timedelta(minutes=20)
        session_service.active_sessions[expired_session.id] = expired_session
        
        # Act
        result = session_service.extend_session(expired_session.id)
        
        # Assert - Contract requirements for 401 response
        assert result is None  # Cannot extend expired session
    
    def test_extend_nonexistent_session(self):
        """Test extending a non-existent session."""
        # Arrange
        from src.services.session_service import SessionService
        
        session_service = SessionService()
        fake_session_id = str(uuid.uuid4())
        
        # Act
        result = session_service.extend_session(fake_session_id)
        
        # Assert - Contract requirements for 401 response
        assert result is None
    
    def test_extend_with_invalid_session_id(self):
        """Test extension with invalid session ID format."""
        # Arrange
        from src.services.session_service import SessionService
        
        session_service = SessionService()
        invalid_ids = [
            "not-a-uuid",
            "12345",
            "",
            None
        ]
        
        # Act & Assert
        for invalid_id in invalid_ids:
            if invalid_id is not None:
                result = session_service.extend_session(invalid_id)
                assert result is None, f"Should reject invalid ID: {invalid_id}"
    
    def test_extend_persists_to_storage(self):
        """Test that extending a session persists it to storage."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        # Create a session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Mock storage persistence
        with patch.object(storage_service, 'persist_session') as mock_persist:
            session_service.storage_service = storage_service
            
            # Act
            extended_session = session_service.extend_session(test_session.id)
            
            # Assert
            assert extended_session is not None
            mock_persist.assert_called_once_with(extended_session)
    
    def test_extend_respects_max_session_duration(self):
        """Test that extension respects maximum session duration."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create a session that's been active for 3.5 hours
        old_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15,
            max_session_hours=4
        )
        # Set creation to 3.5 hours ago
        old_session.created_at = datetime.now() - timedelta(hours=3.5)
        old_session.last_activity_at = datetime.now() - timedelta(minutes=5)
        session_service.active_sessions[old_session.id] = old_session
        
        # Act
        extended_session = session_service.extend_session(old_session.id)
        
        # Assert
        if extended_session:  # May be None if max duration exceeded
            # Check that session won't exceed 4 hours total
            max_allowed = old_session.created_at + timedelta(hours=4)
            assert extended_session.expires_at <= max_allowed