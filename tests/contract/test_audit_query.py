"""Contract test for GET /audit/query endpoint.

Tests the audit query API contract as defined in audit-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import json
import uuid
from pathlib import Path


class TestAuditQueryContract:
    """Contract tests for audit query endpoint."""
    
    def test_query_all_events(self):
        """Test querying all audit events."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log some events
            events_to_log = [
                {"event_type": "LOGIN_SUCCESS", "username": "user1", "success": True},
                {"event_type": "SESSION_CREATED", "username": "user1", "success": True},
                {"event_type": "LOGIN_FAILURE", "username": "user2", "success": False},
            ]
            
            for event in events_to_log:
                audit_service.log_event(**event)
            
            # Act - Query all
            result = audit_service.query_events()
            
            # Assert - Contract requirements
            assert result is not None
            assert 'events' in result
            assert 'total' in result
            assert 'has_more' in result
            
            assert result['total'] == 3
            assert len(result['events']) == 3
            assert result['has_more'] is False
    
    def test_query_by_username(self):
        """Test querying events filtered by username."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log events for different users
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user1", success=True)
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user2", success=True)
            audit_service.log_event(event_type="SESSION_CREATED", username="user1", success=True)
            
            # Act - Query for user1
            result = audit_service.query_events(username="user1")
            
            # Assert
            assert result['total'] == 2
            assert all(e['username'] == "user1" for e in result['events'])
    
    def test_query_by_event_type(self):
        """Test querying events filtered by event type."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log different event types
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user1", success=True)
            audit_service.log_event(event_type="LOGIN_FAILURE", username="user2", success=False)
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user3", success=True)
            
            # Act - Query for LOGIN_SUCCESS
            result = audit_service.query_events(event_type="LOGIN_SUCCESS")
            
            # Assert
            assert result['total'] == 2
            assert all(e['event_type'] == "LOGIN_SUCCESS" for e in result['events'])
    
    def test_query_by_date_range(self):
        """Test querying events within a date range."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log events with different timestamps
            now = datetime.now()
            
            # Mock time for consistent testing
            with patch('src.services.audit_service.datetime') as mock_dt:
                # Event 1: 2 hours ago
                mock_dt.now.return_value = now - timedelta(hours=2)
                mock_dt.fromisoformat = datetime.fromisoformat
                audit_service.log_event(event_type="LOGIN_SUCCESS", username="user1", success=True)
                
                # Event 2: 1 hour ago
                mock_dt.now.return_value = now - timedelta(hours=1)
                audit_service.log_event(event_type="SESSION_CREATED", username="user1", success=True)
                
                # Event 3: Now
                mock_dt.now.return_value = now
                audit_service.log_event(event_type="SESSION_TERMINATED", username="user1", success=True)
            
            # Act - Query last 90 minutes
            from_date = now - timedelta(minutes=90)
            to_date = now
            result = audit_service.query_events(from_date=from_date, to_date=to_date)
            
            # Assert - Should get events 2 and 3
            assert result['total'] == 2
    
    def test_query_with_limit(self):
        """Test querying with result limit."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log many events
            for i in range(10):
                audit_service.log_event(
                    event_type="LOGIN_SUCCESS",
                    username=f"user{i}",
                    success=True
                )
            
            # Act - Query with limit
            result = audit_service.query_events(limit=5)
            
            # Assert
            assert len(result['events']) == 5
            assert result['total'] == 10
            assert result['has_more'] is True
    
    def test_query_event_schema(self):
        """Test that queried events match contract schema."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log an event with all fields
            session_id = str(uuid.uuid4())
            audit_service.log_event(
                event_type="SESSION_CREATED",
                username="testuser",
                session_id=session_id,
                success=True,
                details={"key": "value"}
            )
            
            # Act
            result = audit_service.query_events()
            
            # Assert - Check schema
            assert len(result['events']) == 1
            event = result['events'][0]
            
            # Required fields
            assert 'id' in event
            assert 'event_type' in event
            assert 'timestamp' in event
            assert 'username' in event
            assert 'success' in event
            
            # Optional fields
            assert 'session_id' in event
            assert 'details' in event
            
            # Field types
            assert isinstance(event['id'], str)
            uuid.UUID(event['id'], version=4)  # Valid UUID4
            assert event['event_type'] == "SESSION_CREATED"
            assert isinstance(event['timestamp'], str)  # ISO-8601
            assert event['username'] == "testuser"
            assert event['session_id'] == session_id
            assert event['success'] is True
            assert event['details'] == {"key": "value"}
    
    def test_query_empty_results(self):
        """Test querying when no events match criteria."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log some events
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user1", success=True)
            
            # Act - Query for non-existent user
            result = audit_service.query_events(username="nonexistent")
            
            # Assert
            assert result['total'] == 0
            assert result['events'] == []
            assert result['has_more'] is False
    
    def test_query_combined_filters(self):
        """Test querying with multiple filters combined."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log various events
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user1", success=True)
            audit_service.log_event(event_type="LOGIN_FAILURE", username="user1", success=False)
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user2", success=True)
            audit_service.log_event(event_type="SESSION_CREATED", username="user1", success=True)
            
            # Act - Query with multiple filters
            result = audit_service.query_events(
                username="user1",
                event_type="LOGIN_SUCCESS"
            )
            
            # Assert - Only user1's LOGIN_SUCCESS
            assert result['total'] == 1
            assert result['events'][0]['username'] == "user1"
            assert result['events'][0]['event_type'] == "LOGIN_SUCCESS"
    
    def test_query_invalid_parameters(self):
        """Test query with invalid parameters."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        
        # Test invalid event type
        with pytest.raises(ValueError, match="Invalid event type"):
            audit_service.query_events(event_type="INVALID_TYPE")
        
        # Test invalid limit
        with pytest.raises(ValueError, match="limit"):
            audit_service.query_events(limit=0)
        
        with pytest.raises(ValueError, match="limit"):
            audit_service.query_events(limit=1001)  # Over max
    
    def test_query_ordering(self):
        """Test that events are returned in chronological order."""
        # Arrange
        from src.services.audit_service import AuditService
        import tempfile
        import time
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            
            # Log events with slight delays
            audit_service.log_event(event_type="LOGIN_SUCCESS", username="user1", success=True)
            time.sleep(0.01)
            audit_service.log_event(event_type="SESSION_CREATED", username="user1", success=True)
            time.sleep(0.01)
            audit_service.log_event(event_type="SESSION_TERMINATED", username="user1", success=True)
            
            # Act
            result = audit_service.query_events()
            
            # Assert - Events should be in order
            timestamps = [
                datetime.fromisoformat(e['timestamp'])
                for e in result['events']
            ]
            assert timestamps == sorted(timestamps)