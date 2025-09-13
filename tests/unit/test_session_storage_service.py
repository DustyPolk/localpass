"""Unit tests for SessionStorageService."""

import os
import tempfile
import shutil
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.services.storage.session_storage_service import SessionStorageService
from src.models.session import Session
from src.models.session_file import SessionFile


@pytest.fixture
def temp_storage_dir():
    """Create temporary storage directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def storage_service(temp_storage_dir):
    """Create SessionStorageService with temp directory."""
    with patch('src.services.storage.session_storage_service.platformdirs.user_data_dir') as mock_dir:
        mock_dir.return_value = temp_storage_dir
        service = SessionStorageService()
        return service


@pytest.fixture
def sample_session():
    """Create a sample session for testing."""
    from datetime import datetime
    import uuid
    base_time = datetime.fromtimestamp(1234567890)
    return Session(
        id=str(uuid.uuid4()),
        username="testuser",
        derived_key=b"0123456789abcdef" * 2,  # 32 bytes
        created_at=base_time,
        last_activity_at=base_time
    )


class TestSessionStorageService:
    """Test SessionStorageService functionality."""
    
    def test_init_creates_storage_directory(self, temp_storage_dir):
        """Test that initialization creates storage directory."""
        new_dir = os.path.join(temp_storage_dir, "new_dir")
        with patch('src.services.storage.session_storage_service.platformdirs.user_data_dir') as mock_dir:
            mock_dir.return_value = new_dir
            
            service = SessionStorageService()
            
            assert service.session_dir.exists()
            assert service.session_dir.is_dir()
            # Check permissions (0o700)
            assert oct(service.session_dir.stat().st_mode)[-3:] == "700"
    
    def test_persist_session_creates_encrypted_file(self, storage_service, sample_session):
        """Test that persist_session creates encrypted session file."""
        result = storage_service.persist_session(sample_session)
        
        assert result is not None
        assert result['encrypted'] is True
        assert 'file_path' in result
        
        # Check file was created
        session_file = storage_service.session_dir / "session.enc"
        assert session_file.exists()
        
        # Check file permissions (0o600)
        assert oct(session_file.stat().st_mode)[-3:] == "600"
        
        # Check file is encrypted (not readable as JSON)
        with open(session_file, 'rb') as f:
            content = f.read()
            # Should be encrypted bytes, not readable text
            assert b"testuser" not in content  # Should be encrypted
    
    def test_load_session_decrypts_correctly(self, storage_service, sample_session):
        """Test that load_session correctly decrypts stored session."""
        # First persist the session
        storage_service.persist_session(sample_session)
        
        # Then load it back
        loaded_session = storage_service.load_session()
        
        assert loaded_session is not None
        assert loaded_session.id == sample_session.id
        assert loaded_session.username == sample_session.username
        assert loaded_session.created_at == sample_session.created_at
        assert loaded_session.last_activity_at == sample_session.last_activity_at
        # Note: derived_key is not persisted for security
    
    def test_load_nonexistent_session_returns_none(self, storage_service):
        """Test that loading nonexistent session returns None."""
        result = storage_service.load_session("nonexistent-session")
        assert result is None
    
    def test_delete_session_removes_file(self, storage_service, sample_session):
        """Test that delete_session removes the session file."""
        # First persist the session
        storage_service.persist_session(sample_session)
        session_file = storage_service.session_dir / f"{sample_session.id}.session"
        assert session_file.exists()
        
        # Delete the session
        result = storage_service.delete_session(sample_session.id)
        
        assert result is True
        assert not session_file.exists()
    
    def test_delete_nonexistent_session_returns_false(self, storage_service):
        """Test that deleting nonexistent session returns False."""
        result = storage_service.delete_session("nonexistent-session")
        assert result is False
    
    def test_list_sessions_returns_session_ids(self, storage_service):
        """Test that list_sessions returns all session IDs."""
        # Create multiple sessions
        from datetime import datetime
        import uuid
        sessions = [
            Session(id=str(uuid.uuid4()), username="user", derived_key=b"key" * 8)
            for i in range(3)
        ]
        
        for session in sessions:
            storage_service.persist_session(session)
        
        session_ids = storage_service.list_sessions()
        
        assert len(session_ids) == 3
        for session in sessions:
            assert session.id in session_ids
    
    def test_cleanup_expired_sessions_removes_expired(self, storage_service):
        """Test that cleanup removes expired sessions."""
        from datetime import datetime, timedelta
        current_time = datetime.now()
        
        # Create expired and active sessions
        import uuid
        expired_session = Session(
            id=str(uuid.uuid4()), 
            username="user", 
            derived_key=b"key" * 8,
            created_at=current_time - timedelta(hours=1),
            last_activity_at=current_time - timedelta(minutes=20),  # Expired (>15 min)
            idle_timeout_minutes=15
        )
        active_session = Session(
            id=str(uuid.uuid4()), 
            username="user", 
            derived_key=b"key" * 8,
            created_at=current_time - timedelta(minutes=5),
            last_activity_at=current_time - timedelta(minutes=5),   # Active (<15 min)
            idle_timeout_minutes=15
        )
        
        storage_service.persist_session(expired_session)
        storage_service.persist_session(active_session)
        
        # Cleanup expired sessions
        count = storage_service.cleanup_expired_sessions()
        
        assert count == 1
        
        # Check that only active session remains
        remaining_ids = storage_service.list_sessions()
        assert active_session.id in remaining_ids
        assert expired_session.id not in remaining_ids
    
    def test_get_session_info_returns_metadata(self, storage_service, sample_session):
        """Test that get_session_info returns session metadata."""
        storage_service.persist_session(sample_session)
        
        info = storage_service.get_session_info(sample_session.id)
        
        assert info is not None
        assert info['id'] == sample_session.id
        assert info['username'] == sample_session.username
        assert 'created_at' in info
        assert 'expires_at' in info
        assert 'last_activity' in info
    
    def test_encryption_uses_pbkdf2_key_derivation(self, storage_service, sample_session):
        """Test that encryption uses PBKDF2 for key derivation."""
        with patch('src.services.storage.session_storage_service.PBKDF2HMAC') as mock_pbkdf2:
            mock_pbkdf2.return_value.derive.return_value = b"derived_key_32_bytes_long_test!!"
            
            storage_service.persist_session(sample_session)
            
            # Verify PBKDF2HMAC was instantiated
            mock_pbkdf2.assert_called_once()
    
    def test_file_permissions_are_secure(self, storage_service, sample_session):
        """Test that session files have secure permissions."""
        storage_service.persist_session(sample_session)
        
        session_file = storage_service.session_dir / f"{sample_session.id}.session"
        file_mode = session_file.stat().st_mode
        
        # Check that file is readable/writable by owner only (0o600)
        assert oct(file_mode)[-3:] == "600"
    
    def test_corruption_handling(self, storage_service, sample_session):
        """Test handling of corrupted session files."""
        # Create a corrupted session file
        session_file = storage_service.session_dir / f"{sample_session.id}.session"
        session_file.write_text("corrupted_data")
        session_file.chmod(0o600)
        
        # Attempt to load corrupted session
        result = storage_service.load_session(sample_session.id)
        
        assert result is None  # Should return None for corrupted files
    
    def test_concurrent_access_safety(self, storage_service, sample_session):
        """Test that concurrent access doesn't corrupt files."""
        # This is a basic test - real concurrent testing would need threading
        storage_service.persist_session(sample_session)
        
        # Simulate concurrent reads
        session1 = storage_service.load_session(sample_session.id)
        session2 = storage_service.load_session(sample_session.id)
        
        assert session1 is not None
        assert session2 is not None
        assert session1.id == session2.id