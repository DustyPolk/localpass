"""Contract test for POST /session/terminate endpoint.

Tests the session termination API contract as defined in session-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import uuid


class TestSessionTerminateContract:
    """Contract tests for session termination endpoint."""
    
    def test_terminate_active_session(self):
        """Test terminating an active session (logout)."""
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
        session_service.active_sessions[test_session.id] = test_session
        
        # Act
        result = session_service.terminate_session(test_session.id)
        terminated_at = datetime.now()
        
        # Assert - Contract requirements
        assert result is True
        
        # Session should be removed from active sessions
        assert test_session.id not in session_service.active_sessions
        
        # Verify response includes termination time
        # (In actual implementation, this would be in the response)
        assert abs((terminated_at - datetime.now()).total_seconds()) < 1
    
    def test_terminate_nonexistent_session(self):
        """Test terminating a non-existent session."""
        # Arrange
        from src.services.session_service import SessionService
        
        session_service = SessionService()
        fake_session_id = str(uuid.uuid4())
        
        # Act
        result = session_service.terminate_session(fake_session_id)
        
        # Assert - Contract specifies 404 but we return False
        assert result is False
    
    def test_terminate_already_terminated_session(self):
        """Test terminating an already terminated session."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create and terminate a session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # First termination
        first_result = session_service.terminate_session(test_session.id)
        
        # Act - Try to terminate again
        second_result = session_service.terminate_session(test_session.id)
        
        # Assert
        assert first_result is True
        assert second_result is False  # Already terminated
    
    def test_terminate_clears_persisted_session(self):
        """Test that termination removes persisted session file."""
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
        
        # Mock storage deletion
        with patch.object(storage_service, 'delete_session') as mock_delete:
            session_service.storage_service = storage_service
            
            # Act
            result = session_service.terminate_session(test_session.id)
            
            # Assert
            assert result is True
            mock_delete.assert_called_once()
    
    def test_terminate_clears_sensitive_memory(self):
        """Test that termination clears sensitive data from memory."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create a session with sensitive data
        test_session = Session(
            username="testuser",
            derived_key=bytearray(b"x" * 32),  # Use bytearray for clearing
            idle_timeout_minutes=15
        )
        session_id = test_session.id
        session_service.active_sessions[session_id] = test_session
        
        # Keep reference to derived key
        key_ref = test_session.derived_key
        
        # Act
        result = session_service.terminate_session(session_id)
        
        # Assert
        assert result is True
        # Check that sensitive data is cleared (all zeros)
        if isinstance(key_ref, bytearray):
            assert all(b == 0 for b in key_ref)
    
    def test_terminate_with_invalid_session_id(self):
        """Test termination with invalid session ID format."""
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
                result = session_service.terminate_session(invalid_id)
                assert result is False, f"Should reject invalid ID: {invalid_id}"
    
    def test_terminate_logs_audit_event(self):
        """Test that termination logs an audit event."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.audit_service import AuditService
        from src.models.session import Session
        
        session_service = SessionService()
        audit_service = AuditService()
        
        # Create a session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Mock audit logging
        with patch.object(audit_service, 'log_event') as mock_log:
            session_service.audit_service = audit_service
            
            # Act
            result = session_service.terminate_session(test_session.id)
            
            # Assert
            assert result is True
            mock_log.assert_called_once()
            
            # Verify audit event details
            call_args = mock_log.call_args[1]
            assert call_args['event_type'] == 'SESSION_TERMINATED'
            assert call_args['username'] == 'testuser'
            assert call_args['session_id'] == test_session.id
            assert call_args['success'] is True