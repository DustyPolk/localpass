"""Contract test for POST /audit/log endpoint.

Tests the audit logging API contract as defined in audit-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, mock_open
import json
import uuid
from pathlib import Path


class TestAuditLogContract:
    """Contract tests for audit logging endpoint."""
    
    def test_log_login_success_event(self):
        """Test logging a successful login event."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        
        event_data = {
            "event_type": "LOGIN_SUCCESS",
            "username": "testuser",
            "session_id": str(uuid.uuid4()),
            "success": True,
            "details": {
                "ip_address": "127.0.0.1",
                "user_agent": "LocalPass CLI v1.0"
            }
        }
        
        # Act
        result = audit_service.log_event(**event_data)
        
        # Assert - Contract requirements
        assert result is not None
        assert 'event_id' in result
        assert 'logged_at' in result
        
        # Verify event_id is valid UUID
        event_id = result['event_id']
        assert isinstance(event_id, str)
        uuid.UUID(event_id, version=4)
        
        # Verify logged_at is recent
        logged_at = datetime.fromisoformat(result['logged_at'])
        assert abs((logged_at - datetime.now()).total_seconds()) < 2
    
    def test_log_login_failure_event(self):
        """Test logging a failed login event."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        
        event_data = {
            "event_type": "LOGIN_FAILURE",
            "username": "testuser",
            "session_id": None,  # No session for failed login
            "success": False,
            "details": {
                "reason": "Invalid password",
                "attempts_remaining": 3
            }
        }
        
        # Act
        result = audit_service.log_event(**event_data)
        
        # Assert
        assert result is not None
        assert 'event_id' in result
        assert 'logged_at' in result
    
    def test_log_session_lifecycle_events(self):
        """Test logging various session lifecycle events."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        session_id = str(uuid.uuid4())
        
        lifecycle_events = [
            "SESSION_CREATED",
            "SESSION_EXTENDED",
            "SESSION_VALIDATED",
            "SESSION_EXPIRED",
            "SESSION_TERMINATED"
        ]
        
        for event_type in lifecycle_events:
            event_data = {
                "event_type": event_type,
                "username": "testuser",
                "session_id": session_id,
                "success": True,
                "details": {}
            }
            
            # Act
            result = audit_service.log_event(**event_data)
            
            # Assert
            assert result is not None
            assert 'event_id' in result
            assert 'logged_at' in result
    
    def test_log_event_validation(self):
        """Test that event data is validated."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        
        # Test invalid event type
        with pytest.raises(ValueError, match="Invalid event type"):
            audit_service.log_event(
                event_type="INVALID_EVENT",
                username="testuser",
                success=True
            )
        
        # Test missing username
        with pytest.raises(ValueError, match="Username.*required"):
            audit_service.log_event(
                event_type="LOGIN_SUCCESS",
                username="",
                success=True
            )
        
        # Test invalid session_id format
        with pytest.raises(ValueError, match="Invalid session ID"):
            audit_service.log_event(
                event_type="SESSION_CREATED",
                username="testuser",
                session_id="not-a-uuid",
                success=True
            )
    
    def test_log_event_persistence(self):
        """Test that events are persisted to file."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            audit_file = Path(tmpdir) / "audit.log"
            
            event_data = {
                "event_type": "LOGIN_SUCCESS",
                "username": "testuser",
                "session_id": str(uuid.uuid4()),
                "success": True,
                "details": {}
            }
            
            # Act
            result = audit_service.log_event(**event_data)
            
            # Assert - File should exist
            assert audit_file.exists()
            
            # Verify content is JSON Lines format
            with open(audit_file, 'r') as f:
                lines = f.readlines()
                assert len(lines) == 1
                
                # Parse the JSON line
                logged_event = json.loads(lines[0])
                assert logged_event['event_type'] == "LOGIN_SUCCESS"
                assert logged_event['username'] == "testuser"
                assert logged_event['success'] is True
    
    def test_log_event_append_only(self):
        """Test that events are appended, not overwritten."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            audit_file = Path(tmpdir) / "audit.log"
            
            # Log multiple events
            events = [
                {"event_type": "LOGIN_SUCCESS", "username": "user1", "success": True},
                {"event_type": "SESSION_CREATED", "username": "user1", "success": True},
                {"event_type": "SESSION_TERMINATED", "username": "user1", "success": True}
            ]
            
            # Act
            for event in events:
                audit_service.log_event(**event)
            
            # Assert - All events should be in file
            with open(audit_file, 'r') as f:
                lines = f.readlines()
                assert len(lines) == 3
                
                # Verify each event
                for i, line in enumerate(lines):
                    logged_event = json.loads(line)
                    assert logged_event['event_type'] == events[i]['event_type']
    
    def test_log_event_includes_timestamp(self):
        """Test that logged events include accurate timestamps."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        before_time = datetime.now()
        
        event_data = {
            "event_type": "LOGIN_SUCCESS",
            "username": "testuser",
            "success": True
        }
        
        # Act
        result = audit_service.log_event(**event_data)
        after_time = datetime.now()
        
        # Assert
        logged_at = datetime.fromisoformat(result['logged_at'])
        assert before_time <= logged_at <= after_time
    
    def test_log_event_details_structure(self):
        """Test that event details are properly structured."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            audit_file = Path(tmpdir) / "audit.log"
            
            complex_details = {
                "ip_address": "192.168.1.1",
                "user_agent": "LocalPass CLI",
                "metadata": {
                    "version": "1.0.0",
                    "platform": "linux"
                },
                "tags": ["security", "authentication"]
            }
            
            event_data = {
                "event_type": "LOGIN_SUCCESS",
                "username": "testuser",
                "session_id": str(uuid.uuid4()),
                "success": True,
                "details": complex_details
            }
            
            # Act
            audit_service.log_event(**event_data)
            
            # Assert
            with open(audit_file, 'r') as f:
                logged_event = json.loads(f.readline())
                assert logged_event['details'] == complex_details
    
    def test_log_event_error_handling(self):
        """Test error handling for logging failures."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        
        # Mock file write to fail
        with patch('builtins.open', side_effect=IOError("Disk full")):
            event_data = {
                "event_type": "LOGIN_SUCCESS",
                "username": "testuser",
                "success": True
            }
            
            # Act & Assert
            with pytest.raises(IOError):
                audit_service.log_event(**event_data)