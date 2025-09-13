"""Integration test: Explicit logout clears session.

Implements Scenario 4 from quickstart.md:
1. Login
2. Verify session active
3. Logout
4. Try to use a command - should prompt for password

These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
import tempfile
from pathlib import Path


class TestSessionLogoutIntegration:
    """Integration tests for explicit session logout/termination."""
    
    def test_logout_terminates_active_session(self):
        """Test that explicit logout terminates active session."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        
        auth_service = AuthenticationService()
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            auth_service.session_service = session_service
            
            # Login first
            success, session, _ = auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            assert success is True
            assert session is not None
            
            session_id = session.id
            
            # Verify session exists
            assert session_service.validate_session(session_id) is not None
            
            # Act - Logout
            logout_success = auth_service.logout(session_id)
            
            # Assert
            assert logout_success is True
            
            # Session should no longer be valid
            assert session_service.validate_session(session_id) is None
    
    def test_logout_removes_session_file(self):
        """Test that logout removes persistent session file."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        
        auth_service = AuthenticationService()
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            auth_service.session_service = session_service
            
            session_file = Path(tmpdir) / "session.enc"
            
            # Login and verify session file exists
            success, session, _ = auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            assert success is True
            assert session_file.exists()
            
            # Act - Logout
            logout_success = auth_service.logout(session.id)
            
            # Assert
            assert logout_success is True
            assert not session_file.exists()  # File should be deleted
    
    def test_logout_clears_sensitive_memory(self):
        """Test that logout clears sensitive data from memory."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create session with bytearray key for testing
        test_session = Session(
            username="testuser",
            derived_key=bytearray(b"x" * 32),
            idle_timeout_minutes=15
        )
        session_id = test_session.id
        session_service.active_sessions[session_id] = test_session
        
        # Keep reference to sensitive data
        key_ref = test_session.derived_key
        
        # Act - Terminate session
        result = session_service.terminate_session(session_id)
        
        # Assert
        assert result is True
        
        # Session removed from memory
        assert session_id not in session_service.active_sessions
        
        # Sensitive data cleared
        if isinstance(key_ref, bytearray):
            assert all(b == 0 for b in key_ref)
    
    def test_logout_logs_audit_event(self):
        """Test that logout generates audit log entry."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.audit_service import AuditService
        from src.models.session import Session
        from unittest.mock import Mock
        
        session_service = SessionService()
        audit_service = Mock(spec=AuditService)
        session_service.audit_service = audit_service
        
        # Create active session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Act - Logout
        result = session_service.terminate_session(test_session.id)
        
        # Assert
        assert result is True
        
        # Check audit log call
        audit_service.log_event.assert_called()
        call_args = audit_service.log_event.call_args[1]
        assert call_args['event_type'] == 'SESSION_TERMINATED'
        assert call_args['username'] == 'testuser'
        assert call_args['session_id'] == test_session.id
        assert call_args['success'] is True
    
    def test_logout_nonexistent_session_handled_gracefully(self):
        """Test that logging out non-existent session is handled gracefully."""
        # Arrange
        from src.services.session_service import SessionService
        import uuid
        
        session_service = SessionService()
        fake_session_id = str(uuid.uuid4())
        
        # Act - Try to logout non-existent session
        result = session_service.terminate_session(fake_session_id)
        
        # Assert - Should return False but not crash
        assert result is False
    
    def test_multiple_logout_calls_handled(self):
        """Test that multiple logout calls for same session are handled."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_id = test_session.id
        session_service.active_sessions[session_id] = test_session
        
        # Act - Logout multiple times
        first_result = session_service.terminate_session(session_id)
        second_result = session_service.terminate_session(session_id)
        
        # Assert
        assert first_result is True
        assert second_result is False  # Already logged out
    
    def test_logout_requires_reauthentication(self):
        """Test that after logout, commands require re-authentication."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        
        auth_service = AuthenticationService()
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            auth_service.session_service = session_service
            
            # Login
            success, session, _ = auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            assert success is True
            
            # Logout
            logout_success = auth_service.logout(session.id)
            assert logout_success is True
            
            # Act - Try to get current session
            current_session = session_service.get_current_session()
            
            # Assert - No valid session should exist
            assert current_session is None
    
    def test_logout_immediate_termination(self):
        """Test that logout immediately terminates session regardless of remaining time."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create session with lots of time remaining
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_id = test_session.id
        session_service.active_sessions[session_id] = test_session
        
        # Verify session is active with time remaining
        assert test_session.is_active() is True
        remaining = test_session.get_remaining_time()
        assert remaining.total_seconds() > 800  # Almost 15 minutes
        
        # Act - Terminate session
        result = session_service.terminate_session(session_id)
        
        # Assert - Session immediately terminated
        assert result is True
        assert session_id not in session_service.active_sessions
        
        # Should not be able to validate terminated session
        validated = session_service.validate_session(session_id)
        assert validated is None