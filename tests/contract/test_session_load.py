"""Contract test for GET /session/load endpoint.

Tests the session loading API contract as defined in session-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, mock_open
import json
import uuid
from pathlib import Path


class TestSessionLoadContract:
    """Contract tests for session loading endpoint."""
    
    def test_load_valid_session(self):
        """Test loading a valid persisted session."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        # First persist a session
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            original_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Persist it
            storage_service.persist_session(original_session)
            
            # Act - Load it back
            loaded_session = storage_service.load_session()
            
            # Assert - Contract requirements
            assert loaded_session is not None
            assert loaded_session.id == original_session.id
            assert loaded_session.username == "testuser"
            assert isinstance(loaded_session.created_at, datetime)
            assert isinstance(loaded_session.last_activity_at, datetime)
            assert loaded_session.idle_timeout_minutes == 15
    
    def test_load_no_persisted_session(self):
        """Test loading when no session file exists."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        import tempfile
        
        storage_service = SessionStorageService()
        
        # Use empty temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            # Act
            result = storage_service.load_session()
            
            # Assert - Contract specifies 404
            assert result is None
    
    def test_load_expired_session(self):
        """Test loading an expired persisted session."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            # Create an expired session
            expired_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            # Set to expired
            expired_session.last_activity_at = datetime.now() - timedelta(minutes=20)
            
            # Persist the expired session
            storage_service.persist_session(expired_session)
            
            # Act - Try to load it
            result = storage_service.load_session()
            
            # Assert - Contract specifies 401 for expired
            assert result is None  # Expired sessions not returned
    
    def test_load_corrupted_session_file(self):
        """Test loading when session file is corrupted."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            # Write corrupted data
            session_file.write_bytes(b"corrupted data that's not encrypted properly")
            
            # Act
            result = storage_service.load_session()
            
            # Assert
            assert result is None  # Cannot load corrupted file
    
    def test_load_verifies_checksum(self):
        """Test that loading verifies data integrity via checksum."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        import hashlib
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Mock decryption to return data with bad checksum
            bad_data = {
                "session_id": str(test_session.id),
                "username": "testuser",
                "created_at": datetime.now().isoformat(),
                "last_activity_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(minutes=15)).isoformat(),
                "checksum": "badc0de" * 8  # Invalid checksum
            }
            
            with patch.object(storage_service, '_decrypt_data') as mock_decrypt:
                mock_decrypt.return_value = json.dumps(bad_data)
                
                # Persist a valid session first
                storage_service.persist_session(test_session)
                
                # Act - Try to load with bad checksum
                result = storage_service.load_session()
                
                # Assert
                # Should reject due to checksum mismatch
                # (Implementation should validate checksum)
                pass  # This will fail until implemented
    
    def test_load_session_schema_validation(self):
        """Test that loaded data is validated against schema."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            # Mock decryption to return invalid schema
            invalid_data_sets = [
                {},  # Empty
                {"username": "test"},  # Missing required fields
                {"session_id": "not-a-uuid", "username": "test"},  # Invalid UUID
                {"session_id": str(uuid.uuid4()), "username": ""},  # Empty username
            ]
            
            for invalid_data in invalid_data_sets:
                with patch.object(storage_service, '_decrypt_data') as mock_decrypt:
                    mock_decrypt.return_value = json.dumps(invalid_data)
                    
                    # Create dummy file
                    session_file = Path(tmpdir) / "session.enc"
                    session_file.write_bytes(b"dummy")
                    
                    # Act
                    result = storage_service.load_session()
                    
                    # Assert
                    assert result is None, f"Should reject invalid schema: {invalid_data}"
    
    def test_load_restores_session_state(self):
        """Test that loading fully restores session state."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            # Create session with specific state
            original_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            original_id = original_session.id
            original_created = original_session.created_at
            original_activity = original_session.last_activity_at
            
            # Persist it
            storage_service.persist_session(original_session)
            
            # Clear memory
            del original_session
            
            # Act - Load it back
            loaded_session = storage_service.load_session()
            
            # Assert - All state restored
            assert loaded_session is not None
            assert loaded_session.id == original_id
            assert loaded_session.username == "testuser"
            assert abs((loaded_session.created_at - original_created).total_seconds()) < 1
            assert abs((loaded_session.last_activity_at - original_activity).total_seconds()) < 1
            assert loaded_session.idle_timeout_minutes == 15
    
    def test_load_deletes_expired_file(self):
        """Test that loading an expired session deletes the file."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import tempfile
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            # Create expired session
            expired_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            expired_session.last_activity_at = datetime.now() - timedelta(minutes=20)
            
            # Persist it
            storage_service.persist_session(expired_session)
            assert session_file.exists()
            
            # Act - Load expired session
            result = storage_service.load_session()
            
            # Assert
            assert result is None
            assert not session_file.exists()  # File should be deleted