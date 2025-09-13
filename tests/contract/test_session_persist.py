"""Contract test for POST /session/persist endpoint.

Tests the session persistence API contract as defined in session-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, mock_open
import json
import uuid
import os
from pathlib import Path


class TestSessionPersistContract:
    """Contract tests for session persistence endpoint."""
    
    def test_persist_valid_session(self):
        """Test persisting a valid session to encrypted file."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        # Create a valid session
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        
        # Act
        result = storage_service.persist_session(test_session)
        
        # Assert - Contract requirements
        assert result is not None
        assert 'file_path' in result
        assert 'encrypted' in result
        assert result['encrypted'] is True
        
        # Verify file path is absolute
        file_path = Path(result['file_path'])
        assert file_path.is_absolute()
        
        # Verify file name
        assert file_path.name == "session.enc"
    
    def test_persist_creates_encrypted_file(self):
        """Test that persistence creates an encrypted file."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        # Use temp directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act
            result = storage_service.persist_session(test_session)
            
            # Assert
            session_file = Path(tmpdir) / "session.enc"
            assert session_file.exists()
            
            # Verify file is encrypted (not plain JSON)
            with open(session_file, 'rb') as f:
                content = f.read()
                # Should not be readable JSON
                try:
                    json.loads(content)
                    assert False, "File should be encrypted, not plain JSON"
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass  # Expected - file is encrypted
    
    def test_persist_sets_correct_permissions(self):
        """Test that persisted file has 0600 permissions."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        import stat
        
        storage_service = SessionStorageService()
        
        # Use temp directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act
            result = storage_service.persist_session(test_session)
            
            # Assert - Check file permissions
            session_file = Path(result['file_path'])
            if session_file.exists():
                file_stat = session_file.stat()
                file_mode = stat.S_IMODE(file_stat.st_mode)
                assert file_mode == 0o600  # Owner read/write only
    
    def test_persist_session_data_schema(self):
        """Test that persisted data matches contract schema."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        from src.models.session_file import SessionFile
        
        storage_service = SessionStorageService()
        
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        
        # Mock the encryption to inspect data
        with patch.object(storage_service, '_encrypt_data') as mock_encrypt:
            mock_encrypt.return_value = b"encrypted"
            
            # Act
            storage_service.persist_session(test_session)
            
            # Assert - Check data passed to encryption
            call_args = mock_encrypt.call_args[0][0]
            data = json.loads(call_args)
            
            # Verify schema matches contract
            assert 'session_id' in data
            assert 'username' in data
            assert 'created_at' in data
            assert 'last_activity_at' in data
            assert 'expires_at' in data
            assert 'checksum' in data
            
            # Verify data types
            assert isinstance(data['session_id'], str)
            uuid.UUID(data['session_id'], version=4)  # Valid UUID4
            assert isinstance(data['username'], str)
            assert isinstance(data['created_at'], str)  # ISO-8601
            assert isinstance(data['expires_at'], str)  # ISO-8601
            
            # Verify checksum format (SHA-256)
            assert len(data['checksum']) == 64  # SHA-256 hex string
            assert all(c in '0123456789abcdef' for c in data['checksum'])
    
    def test_persist_handles_write_failure(self):
        """Test handling of file write failures."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        test_session = Session(
            username="testuser",
            derived_key=b"x" * 32,
            idle_timeout_minutes=15
        )
        
        # Mock file write to fail
        with patch('builtins.open', side_effect=IOError("Disk full")):
            # Act
            with pytest.raises(IOError):
                storage_service.persist_session(test_session)
    
    def test_persist_atomic_write(self):
        """Test that persistence uses atomic write (temp file + rename)."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Mock to track file operations
            write_calls = []
            original_open = open
            
            def track_open(path, *args, **kwargs):
                write_calls.append(str(path))
                return original_open(path, *args, **kwargs)
            
            with patch('builtins.open', side_effect=track_open):
                # Act
                storage_service.persist_session(test_session)
                
                # Assert - Should write to temp file first
                assert any('.tmp' in call for call in write_calls)
    
    def test_persist_updates_existing_session(self):
        """Test that persisting overwrites existing session file."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            # Create first session
            session1 = Session(
                username="user1",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Create second session
            session2 = Session(
                username="user2",
                derived_key=b"y" * 32,
                idle_timeout_minutes=15
            )
            
            # Act
            result1 = storage_service.persist_session(session1)
            result2 = storage_service.persist_session(session2)
            
            # Assert - Same file path (overwrites)
            assert result1['file_path'] == result2['file_path']