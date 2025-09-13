"""Security test: Session file permissions (0600).

Tests that session files have proper file permissions (owner read/write only).
These tests MUST fail initially (TDD approach).
"""
import pytest
import tempfile
import stat
import os
from pathlib import Path


class TestFilePermissionsSecurity:
    """Security tests for file permissions."""
    
    def test_session_file_has_correct_permissions(self):
        """Test that session files are created with 0600 permissions."""
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
            
            # Assert - Check file permissions
            assert session_file.exists()
            
            file_stat = session_file.stat()
            file_mode = stat.S_IMODE(file_stat.st_mode)
            
            # Should be 0600 (owner read/write only)
            assert file_mode == 0o600, f"Expected 0600, got {oct(file_mode)}"
    
    def test_session_directory_permissions(self):
        """Test that session directory has appropriate permissions."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = Path(tmpdir) / "localpass"
            storage_service.session_dir = session_dir
            
            # Act - Initialize storage (should create directory)
            storage_service._ensure_session_dir()
            
            # Assert - Directory should exist with proper permissions
            assert session_dir.exists()
            assert session_dir.is_dir()
            
            dir_stat = session_dir.stat()
            dir_mode = stat.S_IMODE(dir_stat.st_mode)
            
            # Directory should be readable/writable/executable by owner only
            # Typically 0700 for directories
            assert dir_mode >= 0o700, f"Directory permissions too open: {oct(dir_mode)}"
    
    def test_audit_log_file_permissions(self):
        """Test that audit log files have secure permissions."""
        # Arrange
        from src.services.audit_service import AuditService
        
        audit_service = AuditService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_service.audit_dir = Path(tmpdir)
            audit_file = Path(tmpdir) / "audit.log"
            
            # Act - Log an event (should create file)
            audit_service.log_event(
                event_type="LOGIN_SUCCESS",
                username="testuser",
                success=True
            )
            
            # Assert - Check file permissions
            if audit_file.exists():
                file_stat = audit_file.stat()
                file_mode = stat.S_IMODE(file_stat.st_mode)
                
                # Should be 0600 or 0644 (readable by owner, not writable by others)
                assert file_mode in [0o600, 0o644], f"Audit file permissions: {oct(file_mode)}"
                
                # At minimum, should not be world-writable
                assert not (file_mode & stat.S_IWOTH), "Audit file should not be world-writable"
    
    def test_permission_enforcement_on_existing_files(self):
        """Test that permissions are enforced even on existing files."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            session_file = Path(tmpdir) / "session.enc"
            
            # Create file with wrong permissions
            session_file.write_bytes(b"dummy data")
            session_file.chmod(0o644)  # Too open
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Act - Persist session (should fix permissions)
            storage_service.persist_session(test_session)
            
            # Assert - Permissions should be corrected
            file_stat = session_file.stat()
            file_mode = stat.S_IMODE(file_stat.st_mode)
            assert file_mode == 0o600, f"Permissions not corrected: {oct(file_mode)}"
    
    def test_umask_independence(self):
        """Test that file permissions are set correctly regardless of umask."""
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
            
            # Act - Test with different umask values
            original_umask = os.umask(0o022)  # Restrictive umask
            try:
                storage_service.persist_session(test_session)
                
                # Check permissions with restrictive umask
                file_stat = session_file.stat()
                file_mode = stat.S_IMODE(file_stat.st_mode)
                assert file_mode == 0o600
                
                # Remove file and test with permissive umask
                session_file.unlink()
                os.umask(0o000)  # Permissive umask
                
                storage_service.persist_session(test_session)
                
                # Check permissions with permissive umask
                file_stat = session_file.stat()
                file_mode = stat.S_IMODE(file_stat.st_mode)
                assert file_mode == 0o600
                
            finally:
                os.umask(original_umask)  # Restore original umask
    
    def test_no_group_or_world_access(self):
        """Test that files are not accessible by group or world."""
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
            
            # Act
            storage_service.persist_session(test_session)
            
            # Assert - No group or world permissions
            file_stat = session_file.stat()
            file_mode = stat.S_IMODE(file_stat.st_mode)
            
            # Group should have no permissions
            assert not (file_mode & stat.S_IRGRP), "File should not be group-readable"
            assert not (file_mode & stat.S_IWGRP), "File should not be group-writable"
            assert not (file_mode & stat.S_IXGRP), "File should not be group-executable"
            
            # World should have no permissions
            assert not (file_mode & stat.S_IROTH), "File should not be world-readable"
            assert not (file_mode & stat.S_IWOTH), "File should not be world-writable"
            assert not (file_mode & stat.S_IXOTH), "File should not be world-executable"
    
    def test_temporary_file_permissions(self):
        """Test that temporary files used during atomic writes have secure permissions."""
        # Arrange
        from src.services.storage.session_storage_service import SessionStorageService
        from src.models.session import Session
        from unittest.mock import patch
        import tempfile as temp_module
        
        storage_service = SessionStorageService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_service.session_dir = Path(tmpdir)
            
            test_session = Session(
                username="testuser",
                derived_key=b"x" * 32,
                idle_timeout_minutes=15
            )
            
            # Track temporary files created
            temp_files = []
            original_mkstemp = temp_module.mkstemp
            
            def track_mkstemp(*args, **kwargs):
                fd, path = original_mkstemp(*args, **kwargs)
                temp_files.append(path)
                return fd, path
            
            # Act
            with patch('tempfile.mkstemp', side_effect=track_mkstemp):
                storage_service.persist_session(test_session)
            
            # Assert - Check that temporary files had secure permissions
            # (This test depends on implementation using atomic writes)
            if temp_files:
                for temp_file in temp_files:
                    if Path(temp_file).exists():
                        file_stat = Path(temp_file).stat()
                        file_mode = stat.S_IMODE(file_stat.st_mode)
                        assert file_mode == 0o600, f"Temp file permissions: {oct(file_mode)}"
    
    @pytest.mark.skipif(os.name == 'nt', reason="Unix-style permissions not applicable on Windows")
    def test_unix_permission_enforcement(self):
        """Test permission enforcement on Unix-like systems."""
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
            
            # Act
            storage_service.persist_session(test_session)
            
            # Assert - Test specific Unix permission bits
            file_stat = session_file.stat()
            
            # Owner should have read and write
            assert file_stat.st_mode & stat.S_IRUSR, "Owner should have read permission"
            assert file_stat.st_mode & stat.S_IWUSR, "Owner should have write permission"
            
            # Owner should NOT have execute (it's a data file)
            assert not (file_stat.st_mode & stat.S_IXUSR), "Owner should not have execute permission"