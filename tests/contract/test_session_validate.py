"""Contract test for POST /session/validate endpoint.

Tests the session validation API contract as defined in session-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import uuid


class TestSessionValidateContract:
    """Contract tests for session validation endpoint."""
    
    def test_validate_active_session(self):
        """Test validation of an active, non-expired session."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create a valid session first
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,  # 32-byte key
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Act
        validated_session = session_service.validate_session(test_session.id)
        
        # Assert - Contract requirements
        assert validated_session is not None
        assert validated_session.id == test_session.id
        assert validated_session.username == "testuser"
        assert isinstance(validated_session.created_at, datetime)
        assert isinstance(validated_session.last_activity_at, datetime)
        assert validated_session.is_active() is True
        
        # Verify remaining time
        remaining = validated_session.get_remaining_time()
        assert 0 <= remaining.total_seconds() <= 900  # 0-15 minutes
    
    def test_validate_expired_session(self):
        """Test validation of an expired session."""
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
        # Manually set to expired
        expired_session.last_activity_at = datetime.now() - timedelta(minutes=20)
        session_service.active_sessions[expired_session.id] = expired_session
        
        # Act
        validated_session = session_service.validate_session(expired_session.id)
        
        # Assert - Contract requirements for 401 response
        assert validated_session is None  # Session expired
    
    def test_validate_nonexistent_session(self):
        """Test validation of a non-existent session ID."""
        # Arrange
        from src.services.session_service import SessionService
        
        session_service = SessionService()
        fake_session_id = str(uuid.uuid4())
        
        # Act
        validated_session = session_service.validate_session(fake_session_id)
        
        # Assert - Contract requirements for 401 response
        assert validated_session is None
    
    def test_validate_invalid_session_id_format(self):
        """Test validation with invalid session ID format."""
        # Arrange
        from src.services.session_service import SessionService
        
        session_service = SessionService()
        invalid_ids = [
            "not-a-uuid",
            "12345",
            "",
            None,
            "123e4567-e89b-12d3-a456"  # Incomplete UUID
        ]
        
        # Act & Assert
        for invalid_id in invalid_ids:
            if invalid_id is not None:
                result = session_service.validate_session(invalid_id)
                assert result is None, f"Should reject invalid ID: {invalid_id}"
    
    def test_validate_session_from_persistent_storage(self):
        """Test validation loads session from persistent storage if not in memory."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        # Create a session that exists only in storage
        stored_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        
        # Mock the storage to return our session
        with patch.object(storage_service, 'load_session') as mock_load:
            mock_load.return_value = stored_session
            session_service.storage_service = storage_service
            
            # Act
            validated_session = session_service.validate_session(stored_session.id)
            
            # Assert
            assert validated_session is not None
            assert validated_session.id == stored_session.id
            assert validated_session.username == "testuser"
            mock_load.assert_called_once()
    
    def test_validate_updates_last_activity(self):
        """Test that validation updates the last activity timestamp."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create a session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        original_activity = test_session.last_activity_at
        session_service.active_sessions[test_session.id] = test_session
        
        # Act
        validated_session = session_service.validate_session(test_session.id)
        
        # Assert - Activity should be updated
        assert validated_session is not None
        assert validated_session.last_activity_at >= original_activity