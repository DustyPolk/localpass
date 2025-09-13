"""Integration test: Basic session creation and validation.

Implements Scenario 1 from quickstart.md:
1. Authenticate and create session
2. Verify session persists (within 1 minute)
3. List passwords without re-authentication

These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
import tempfile
import subprocess
import os
from pathlib import Path


class TestSessionBasicIntegration:
    """Integration tests for basic session functionality."""
    
    def test_authenticate_and_create_session(self):
        """Test successful authentication creates a persistent session."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        
        auth_service = AuthenticationService()
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set up test storage location
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            auth_service.session_service = session_service
            
            # Act - Authenticate
            success, session, error = auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            
            # Assert
            assert success is True
            assert session is not None
            assert error is None
            
            # Verify session properties
            assert session.username == "testuser"
            assert session.idle_timeout_minutes == 15
            assert session.is_active() is True
            
            # Verify session is persisted to file
            session_file = Path(tmpdir) / "session.enc"
            assert session_file.exists()
            
            # Verify file permissions
            import stat
            file_stat = session_file.stat()
            assert stat.S_IMODE(file_stat.st_mode) == 0o600
    
    def test_session_persists_between_commands(self):
        """Test that session persists and can be loaded for subsequent commands."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        
        # First command - authenticate
        auth_service1 = AuthenticationService()
        session_service1 = SessionService()
        storage_service1 = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service1.session_dir = Path(tmpdir)
            session_service1.storage_service = storage_service1
            auth_service1.session_service = session_service1
            
            # Create session
            success, original_session, _ = auth_service1.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            assert success is True
            
            # Second command - simulate new process
            auth_service2 = AuthenticationService()
            session_service2 = SessionService()
            storage_service2 = SessionStorageService()
            
            storage_service2.session_dir = Path(tmpdir)
            session_service2.storage_service = storage_service2
            auth_service2.session_service = session_service2
            
            # Act - Load existing session
            loaded_session = session_service2.load_existing_session()
            
            # Assert
            assert loaded_session is not None
            assert loaded_session.id == original_session.id
            assert loaded_session.username == original_session.username
            assert loaded_session.is_active() is True
    
    def test_session_validation_within_timeout(self):
        """Test that session validation works within the timeout period."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            # Create and persist session
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            storage_service.persist_session(test_session)
            
            # Act - Validate session within timeout
            validated_session = session_service.validate_session(test_session.id)
            
            # Assert
            assert validated_session is not None
            assert validated_session.id == test_session.id
            assert validated_session.is_active() is True
            
            # Activity should be updated
            assert validated_session.last_activity_at >= test_session.last_activity_at
    
    def test_session_extends_on_activity(self):
        """Test that using the session extends the timeout."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            # Create session with specific activity time
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            original_activity = test_session.last_activity_at
            original_expires = test_session.expires_at
            
            storage_service.persist_session(test_session)
            
            # Wait a moment
            import time
            time.sleep(0.1)
            
            # Act - Extend session
            extended_session = session_service.extend_session(test_session.id)
            
            # Assert
            assert extended_session is not None
            assert extended_session.last_activity_at > original_activity
            assert extended_session.expires_at > original_expires
            
            # Should still be active
            assert extended_session.is_active() is True
    
    def test_no_reauthentication_within_session(self):
        """Test that commands within session don't require re-authentication."""
        # This is a higher-level integration test that would normally
        # test the CLI commands, but since we're testing the service layer:
        
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
            
            # Authenticate once
            success, session, _ = auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            assert success is True
            
            # Act - Simulate multiple command invocations
            session_checks = []
            for i in range(5):
                # Each "command" checks for valid session
                current_session = session_service.get_current_session()
                session_checks.append(current_session is not None)
                
                if current_session:
                    # Extend session on activity
                    session_service.extend_session(current_session.id)
            
            # Assert - All commands should find valid session
            assert all(session_checks), "All commands should have valid session"
    
    def test_session_remaining_time_accuracy(self):
        """Test that session reports accurate remaining time."""
        # Arrange
        from src.models.session import Session
        from src.services.session_service import SessionService
        
        session_service = SessionService()
        
        # Create session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Act
        remaining = test_session.get_remaining_time()
        
        # Assert
        # Should be close to 15 minutes (900 seconds)
        assert 890 <= remaining.total_seconds() <= 900
        
        # After extension
        extended_session = session_service.extend_session(test_session.id)
        if extended_session:
            new_remaining = extended_session.get_remaining_time()
            assert 890 <= new_remaining.total_seconds() <= 900
    
    def test_session_creation_logs_audit_event(self):
        """Test that session creation generates audit events."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.audit_service import AuditService
        from unittest.mock import Mock, patch
        
        auth_service = AuthenticationService()
        audit_service = Mock(spec=AuditService)
        
        # Wire up audit service
        auth_service.audit_service = audit_service
        
        # Act
        success, session, _ = auth_service.authenticate(
            password="TestPass123!",
            timeout_minutes=15
        )
        
        # Assert
        if success:
            # Should have logged LOGIN_SUCCESS and SESSION_CREATED
            assert audit_service.log_event.call_count >= 1
            
            # Check event types
            call_args_list = audit_service.log_event.call_args_list
            event_types = [call[1]['event_type'] for call in call_args_list]
            assert 'LOGIN_SUCCESS' in event_types or 'SESSION_CREATED' in event_types