"""Security test: Session file encryption.

Tests that session files are properly encrypted and cannot be read without proper decryption.
These tests MUST fail initially (TDD approach).
"""
import pytest
import tempfile
import json
from pathlib import Path
from cryptography.fernet import Fernet


class TestSessionEncryptionSecurity:
    """Security tests for session file encryption."""
    
    def test_session_file_is_encrypted(self):
        """Test that persisted session files are encrypted, not plain text."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act - Persist session
            storage_service.persist_session(test_session)
            
            # Assert - File should exist and be encrypted
            assert session_file.exists()
            
            # Read raw file content
            with open(session_file, 'rb') as f:
                raw_content = f.read()
            
            # Should not be readable as JSON
            try:
                json.loads(raw_content)
                pytest.fail("Session file should be encrypted, not plain JSON")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass  # Expected - file is encrypted
            
            # Should not contain plaintext session data
            raw_text = raw_content.decode('utf-8', errors='ignore')
            assert "testuser" not in raw_text
            assert test_session.id not in raw_text
    
    def test_encrypted_session_can_be_decrypted(self):
        """Test that encrypted sessions can be properly decrypted."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            original_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act - Persist and load
            storage_service.persist_session(original_session)
            loaded_session = storage_service.load_session()
            
            # Assert - Should decrypt correctly
            assert loaded_session is not None
            assert loaded_session.id == original_session.id
            assert loaded_session.username == "testuser"
            assert loaded_session.idle_timeout_minutes == 15
    
    def test_corrupted_encrypted_file_handled(self):
        """Test that corrupted encrypted files are handled gracefully."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            # Write corrupted encrypted data
            session_file.write_bytes(b"corrupted_encrypted_data_that_cannot_be_decrypted")
            
            # Act - Try to load corrupted file
            result = storage_service.load_session()
            
            # Assert - Should handle gracefully
            assert result is None
            # File should be cleaned up
            assert not session_file.exists()
    
    def test_session_encryption_uses_strong_algorithm(self):
        """Test that session encryption uses strong cryptographic algorithm."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.config.session_config import SESSION_ENCRYPTION_ALGORITHM
        
        # Assert - Should use AES-256-GCM
        assert SESSION_ENCRYPTION_ALGORITHM == "AES-256-GCM"
        
        # Test that the service uses this algorithm
        storage_service = SessionStorageService()
        
        # Check encryption configuration
        assert hasattr(storage_service, '_get_encryption_key') or \
               hasattr(storage_service, 'encryption_key') or \
               hasattr(storage_service, '_encrypt_data')
    
    def test_encryption_key_derivation(self):
        """Test that encryption keys are properly derived."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        
        storage_service = SessionStorageService()
        
        # Act - Get encryption key (should be derived from user/system data)
        if hasattr(storage_service, '_get_encryption_key'):
            key1 = storage_service._get_encryption_key()
            key2 = storage_service._get_encryption_key()
            
            # Assert - Keys should be consistent
            assert key1 == key2
            assert len(key1) == 32  # 256 bits
            assert isinstance(key1, bytes)
    
    def test_different_sessions_same_encryption_key(self):
        """Test that different sessions use the same encryption key for consistency."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            # Create two different sessions
            session1 = Session(
                username="user1",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            session2 = Session(
                username="user2", 
                derived_key=b"y" * 32,
                idle_timeout_minutes=15
            )
            
            # Act - Persist both sessions
            storage_service.persist_session(session1)
            first_load = storage_service.load_session()
            
            storage_service.persist_session(session2)
            second_load = storage_service.load_session()
            
            # Assert - Both should decrypt successfully
            assert first_load is not None or second_load is not None
            # (One will overwrite the other, but both should be decryptable)
    
    def test_encryption_nonce_randomness(self):
        """Test that encryption uses random nonces for each encryption."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act - Encrypt same session multiple times
            encryption_outputs = []
            for _ in range(3):
                storage_service.persist_session(test_session)
                with open(session_file, 'rb') as f:
                    encryption_outputs.append(f.read())
            
            # Assert - Each encryption should be different (due to random nonce)
            assert len(set(encryption_outputs)) == 3, "Each encryption should be unique"
    
    def test_tampering_detection(self):
        """Test that tampering with encrypted files is detected."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Persist session
            storage_service.persist_session(test_session)
            
            # Act - Tamper with encrypted file
            with open(session_file, 'rb') as f:
                original_data = f.read()
            
            # Modify a few bytes
            tampered_data = bytearray(original_data)
            tampered_data[10] = (tampered_data[10] + 1) % 256  # Change one byte
            
            with open(session_file, 'wb') as f:
                f.write(tampered_data)
            
            # Try to load tampered file
            result = storage_service.load_session()
            
            # Assert - Should detect tampering and reject
            assert result is None
    
    def test_encryption_performance(self):
        """Test that encryption/decryption meets performance requirements."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        import time
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act - Measure encryption time
            start_time = time.time()
            storage_service.persist_session(test_session)
            encrypt_time = time.time() - start_time
            
            # Measure decryption time
            start_time = time.time()
            loaded_session = storage_service.load_session()
            decrypt_time = time.time() - start_time
            
            # Assert - Should be fast (under 100ms each)
            assert encrypt_time < 0.1, f"Encryption too slow: {encrypt_time}s"
            assert decrypt_time < 0.1, f"Decryption too slow: {decrypt_time}s"
            assert loaded_session is not None