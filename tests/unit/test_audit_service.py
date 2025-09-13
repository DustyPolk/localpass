"""Unit tests for AuditService."""

import os
import tempfile
import shutil
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from src.services.audit_service import AuditService
from src.models.auth_event import AuthEvent, EventType


@pytest.fixture
def temp_audit_dir():
    """Create temporary audit directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def audit_service(temp_audit_dir):
    """Create AuditService with temp directory."""
    with patch('src.services.audit_service.platformdirs.user_data_dir') as mock_dir:
        mock_dir.return_value = temp_audit_dir
        service = AuditService()
        return service


@pytest.fixture
def sample_auth_event():
    """Create sample auth event."""
    return AuthEvent.create_login_success(
        username="testuser",
        session_id="test-session-123",
        details={'source': 'cli'}
    )


class TestAuditService:
    """Test AuditService functionality."""
    
    def test_init_creates_audit_directory(self, temp_audit_dir):
        """Test that initialization creates audit directory."""
        new_dir = os.path.join(temp_audit_dir, "new_audit")
        with patch('src.services.audit_service.platformdirs.user_data_dir') as mock_dir:
            mock_dir.return_value = new_dir
            
            service = AuditService()
            
            assert service.audit_dir.exists()
            assert service.audit_dir.is_dir()
            # Check permissions (0o700)
            assert oct(service.audit_dir.stat().st_mode)[-3:] == "700"
    
    def test_log_event_writes_json_line(self, audit_service, sample_auth_event):
        """Test that log_event writes event as JSON line."""
        result = audit_service.log_event(sample_auth_event)
        
        assert result is True
        
        # Check log file was created
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = audit_service.audit_dir / f"audit-{today}.jsonl"
        assert log_file.exists()
        
        # Check file permissions (0o600)
        assert oct(log_file.stat().st_mode)[-3:] == "600"
        
        # Check content is valid JSON line
        with open(log_file, 'r') as f:
            line = f.readline().strip()
            event_data = json.loads(line)
            
            assert event_data['event_type'] == 'LOGIN_SUCCESS'
            assert event_data['username'] == 'testuser'
            assert event_data['session_id'] == 'test-session-123'
            assert event_data['success'] is True
    
    def test_log_multiple_events_appends_lines(self, audit_service):
        """Test that multiple events are appended to same file."""
        events = [
            AuthEvent.create_login_attempt("user1"),
            AuthEvent.create_login_success("user1", "session-1"),
            AuthEvent.create_session_extended("user1", "session-1")
        ]
        
        for event in events:
            audit_service.log_event(event)
        
        # Check all events are in log file
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = audit_service.audit_dir / f"audit-{today}.jsonl"
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        assert len(lines) == 3
        
        # Verify each line is valid JSON
        for line in lines:
            event_data = json.loads(line.strip())
            assert 'event_type' in event_data
            assert 'timestamp' in event_data
            assert 'username' in event_data
    
    def test_query_events_filters_by_criteria(self, audit_service):
        """Test that query_events filters events correctly."""
        # Create events for different users and types
        events = [
            AuthEvent.create_login_success("alice", "session-1"),
            AuthEvent.create_login_failure("bob", "wrong password"),
            AuthEvent.create_session_extended("alice", "session-1"),
            AuthEvent.create_login_success("charlie", "session-2")
        ]
        
        for event in events:
            audit_service.log_event(event)
        
        # Query by username
        alice_events = audit_service.query_events(username="alice")
        assert len(alice_events) == 2
        assert all(event['username'] == 'alice' for event in alice_events)
        
        # Query by event type
        login_events = audit_service.query_events(event_type="LOGIN_SUCCESS")
        assert len(login_events) == 2
        assert all(event['event_type'] == 'LOGIN_SUCCESS' for event in login_events)
        
        # Query by success status
        failure_events = audit_service.query_events(success=False)
        assert len(failure_events) == 1
        assert failure_events[0]['event_type'] == 'LOGIN_FAILURE'
    
    def test_query_events_with_time_range(self, audit_service):
        """Test that query_events filters by time range."""
        now = datetime.now()
        
        # Create events with specific timestamps
        old_event = AuthEvent(
            event_type="LOGIN_SUCCESS",
            username="user1",
            success=True,
            timestamp=now - timedelta(hours=2)
        )
        
        recent_event = AuthEvent(
            event_type="LOGIN_SUCCESS", 
            username="user2",
            success=True,
            timestamp=now - timedelta(minutes=30)
        )
        
        audit_service.log_event(old_event)
        audit_service.log_event(recent_event)
        
        # Query for events in last hour
        since = now - timedelta(hours=1)
        recent_events = audit_service.query_events(since=since)
        
        assert len(recent_events) == 1
        assert recent_events[0]['username'] == 'user2'
    
    def test_query_events_with_limit(self, audit_service):
        """Test that query_events respects limit parameter."""
        # Create multiple events
        for i in range(10):
            event = AuthEvent.create_login_success(f"user{i}", f"session-{i}")
            audit_service.log_event(event)
        
        # Query with limit
        limited_events = audit_service.query_events(limit=5)
        
        assert len(limited_events) == 5
    
    def test_cleanup_old_logs_removes_expired(self, audit_service):
        """Test that cleanup removes logs older than retention period."""
        # Create log files with different dates
        today = datetime.now()
        old_date = today - timedelta(days=100)  # Older than 90-day retention
        recent_date = today - timedelta(days=30)  # Within retention
        
        old_log = audit_service.audit_dir / f"audit-{old_date.strftime('%Y-%m-%d')}.jsonl"
        recent_log = audit_service.audit_dir / f"audit-{recent_date.strftime('%Y-%m-%d')}.jsonl"
        
        # Create the log files
        old_log.write_text('{"event_type":"LOGIN_SUCCESS","username":"user","success":true}\n')
        recent_log.write_text('{"event_type":"LOGIN_SUCCESS","username":"user","success":true}\n')
        old_log.chmod(0o600)
        recent_log.chmod(0o600)
        
        assert old_log.exists()
        assert recent_log.exists()
        
        # Run cleanup
        removed_count = audit_service.cleanup_old_logs()
        
        assert removed_count == 1
        assert not old_log.exists()
        assert recent_log.exists()
    
    def test_get_audit_stats_returns_metrics(self, audit_service):
        """Test that get_audit_stats returns audit metrics."""
        # Create various events
        events = [
            AuthEvent.create_login_success("user1", "session-1"),
            AuthEvent.create_login_failure("user2", "wrong password"),
            AuthEvent.create_session_created("user1", "session-1"),
            AuthEvent.create_session_expired("user3", "session-2")
        ]
        
        for event in events:
            audit_service.log_event(event)
        
        stats = audit_service.get_audit_stats()
        
        assert stats['total_events'] == 4
        assert stats['success_events'] == 2
        assert stats['failure_events'] == 2
        assert stats['unique_users'] == 3
        assert stats['event_types']['LOGIN_SUCCESS'] == 1
        assert stats['event_types']['LOGIN_FAILURE'] == 1
        assert stats['event_types']['SESSION_CREATED'] == 1
        assert stats['event_types']['SESSION_EXPIRED'] == 1
    
    def test_get_recent_events_returns_latest(self, audit_service):
        """Test that get_recent_events returns most recent events."""
        # Create events over time
        for i in range(10):
            event = AuthEvent.create_login_success(f"user{i}", f"session-{i}")
            audit_service.log_event(event)
        
        recent_events = audit_service.get_recent_events(limit=3)
        
        assert len(recent_events) == 3
        # Should be in reverse chronological order (most recent first)
        timestamps = [datetime.fromisoformat(event['timestamp']) for event in recent_events]
        assert timestamps == sorted(timestamps, reverse=True)
    
    def test_log_file_rotation_by_date(self, audit_service):
        """Test that log files are created per date."""
        today = datetime.now()
        yesterday = today - timedelta(days=1)
        
        # Mock different dates
        with patch('src.services.audit_service.datetime') as mock_datetime:
            # Log event "yesterday"
            mock_datetime.now.return_value = yesterday
            mock_datetime.strftime = datetime.strftime
            event1 = AuthEvent.create_login_success("user1", "session-1")
            audit_service.log_event(event1)
            
            # Log event "today"
            mock_datetime.now.return_value = today
            event2 = AuthEvent.create_login_success("user2", "session-2")
            audit_service.log_event(event2)
        
        # Check separate log files were created
        yesterday_log = audit_service.audit_dir / f"audit-{yesterday.strftime('%Y-%m-%d')}.jsonl"
        today_log = audit_service.audit_dir / f"audit-{today.strftime('%Y-%m-%d')}.jsonl"
        
        assert yesterday_log.exists()
        assert today_log.exists()
        
        # Check content
        with open(yesterday_log, 'r') as f:
            yesterday_data = json.loads(f.readline().strip())
            assert yesterday_data['username'] == 'user1'
        
        with open(today_log, 'r') as f:
            today_data = json.loads(f.readline().strip())
            assert today_data['username'] == 'user2'
    
    def test_concurrent_logging_safety(self, audit_service):
        """Test that concurrent logging is handled safely."""
        # Simulate concurrent writes to same log file
        events = [
            AuthEvent.create_login_success(f"user{i}", f"session-{i}")
            for i in range(5)
        ]
        
        # Log all events (simulating concurrent writes)
        results = []
        for event in events:
            result = audit_service.log_event(event)
            results.append(result)
        
        # All writes should succeed
        assert all(results)
        
        # Verify all events were logged
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = audit_service.audit_dir / f"audit-{today}.jsonl"
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        assert len(lines) == 5
    
    def test_malformed_log_file_handling(self, audit_service):
        """Test handling of malformed log files during queries."""
        # Create log file with invalid JSON
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = audit_service.audit_dir / f"audit-{today}.jsonl"
        
        with open(log_file, 'w') as f:
            f.write('{"valid": "json"}\n')
            f.write('invalid json line\n')  # Malformed line
            f.write('{"another": "valid"}\n')
        
        log_file.chmod(0o600)
        
        # Query should skip malformed lines and return valid ones
        events = audit_service.query_events()
        
        assert len(events) == 2  # Only valid JSON lines
        assert events[0]['valid'] == 'json'
        assert events[1]['another'] == 'valid'