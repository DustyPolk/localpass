"""Integration test: Session timeout extension.

Implements Scenario 2 from quickstart.md:
1. Login
2. Wait 14 minutes (or modify system time)
3. Use a command to extend session
4. Check session status shows extended time

These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
import tempfile
import time
from unittest.mock import patch
from pathlib import Path


class TestSessionExtensionIntegration:
    """Integration tests for session timeout extension."""
    
    def test_session_extends_on_activity_near_timeout(self):
        """Test that activity near timeout extends the session."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            # Create session that's almost expired (14 minutes old)
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            # Set activity to 14 minutes ago
            test_session.last_activity_at = datetime.now() - timedelta(minutes=14)
            storage_service.persist_session(test_session)
            
            # Verify session is still active (1 minute left)
            assert test_session.is_active() is True
            remaining = test_session.get_remaining_time()
            assert 0 < remaining.total_seconds() <= 60  # ~1 minute left
            
            # Act - Use session (extend it)
            extended_session = session_service.extend_session(test_session.id)
            
            # Assert - Session should be extended
            assert extended_session is not None
            assert extended_session.is_active() is True
            
            # Should have close to 15 minutes again
            new_remaining = extended_session.get_remaining_time()
            assert 890 <= new_remaining.total_seconds() <= 900  # ~15 minutes
    
    def test_rolling_timeout_behavior(self):
        """Test that each activity resets the 15-minute timer."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            # Create fresh session
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            storage_service.persist_session(test_session)
            
            # Track extension times
            extension_times = []
            
            # Act - Extend session multiple times with delays
            for i in range(3):
                if i > 0:
                    time.sleep(0.1)  # Small delay between extensions
                
                extended = session_service.extend_session(test_session.id)
                assert extended is not None
                extension_times.append(extended.last_activity_at)
            
            # Assert - Each extension should update the activity time
            for i in range(1, len(extension_times)):
                assert extension_times[i] > extension_times[i-1]
            
            # Final session should still have ~15 minutes
            final_remaining = extended.get_remaining_time()
            assert 890 <= final_remaining.total_seconds() <= 900
    
    def test_session_extension_persistence(self):
        """Test that session extensions are persisted to storage."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            # Create session
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            storage_service.persist_session(test_session)
            original_activity = test_session.last_activity_at
            
            # Act - Extend session
            extended_session = session_service.extend_session(test_session.id)
            assert extended_session is not None
            
            # Simulate new process - load from storage
            new_session_service = SessionService()
            new_storage_service = SessionStorageService()
            new_storage_service.session_dir = Path(tmpdir)
            new_session_service.storage_service = new_storage_service
            
            loaded_session = new_storage_service.load_session()
            
            # Assert - Loaded session should have extended time
            assert loaded_session is not None
            assert loaded_session.last_activity_at > original_activity
            assert loaded_session.is_active() is True
    
    def test_multiple_extensions_within_max_duration(self):
        """Test multiple extensions don't exceed maximum session duration."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            # Create session that's been active for 3.5 hours
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15,
                max_session_hours=4
            )
            # Set creation to 3.5 hours ago
            test_session.created_at = datetime.now() - timedelta(hours=3.5)
            test_session.last_activity_at = datetime.now() - timedelta(minutes=10)
            storage_service.persist_session(test_session)
            
            # Act - Try to extend session
            extended_session = session_service.extend_session(test_session.id)
            
            # Assert - Should still allow extension but respect max duration
            if extended_session:
                # Session should expire at max 4 hours from creation
                max_allowed_expiry = test_session.created_at + timedelta(hours=4)
                
                # The actual expiry should not exceed the max duration
                # It might be earlier due to idle timeout
                assert extended_session.expires_at <= max_allowed_expiry
    
    def test_session_extension_audit_logging(self):
        """Test that session extensions are logged to audit."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.audit_service import AuditService
        from src.models.session import Session
        from unittest.mock import Mock
        
        session_service = SessionService()
        audit_service = Mock(spec=AuditService)
        session_service.audit_service = audit_service
        
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Act
        extended_session = session_service.extend_session(test_session.id)
        
        # Assert
        if extended_session:
            # Should log SESSION_EXTENDED event
            audit_service.log_event.assert_called()
            call_args = audit_service.log_event.call_args[1]
            assert call_args['event_type'] == 'SESSION_EXTENDED'
            assert call_args['username'] == 'testuser'
            assert call_args['session_id'] == test_session.id
            assert call_args['success'] is True
    
    def test_concurrent_session_extensions(self):
        """Test handling of concurrent session extension attempts."""
        # Arrange
        from src.services.session_service import SessionService
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import threading
        
        session_service = SessionService()
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_service.storage_service = storage_service
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            storage_service.persist_session(test_session)
            
            # Act - Simulate concurrent extensions
            results = []
            
            def extend_session():
                result = session_service.extend_session(test_session.id)
                results.append(result is not None)
            
            threads = [threading.Thread(target=extend_session) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # Assert - All extensions should succeed (or at least not crash)
            assert len(results) == 3
            # At least one should succeed
            assert any(results)
    
    def test_extension_updates_expiry_calculation(self):
        """Test that extension properly recalculates expiry time."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        session_service.active_sessions[test_session.id] = test_session
        
        # Record times before extension
        before_extension = datetime.now()
        original_expires = test_session.expires_at
        
        # Act - Extend session
        extended_session = session_service.extend_session(test_session.id)
        after_extension = datetime.now()
        
        # Assert
        assert extended_session is not None
        
        # New expiry should be ~15 minutes from extension time
        expected_min_expiry = before_extension + timedelta(minutes=15)
        expected_max_expiry = after_extension + timedelta(minutes=15)
        
        assert expected_min_expiry <= extended_session.expires_at <= expected_max_expiry
        assert extended_session.expires_at > original_expires