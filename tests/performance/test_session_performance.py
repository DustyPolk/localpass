"""Performance tests for session operations.

Validates that session operations meet performance requirements:
- Session validation < 10ms
- Memory clearing < 1ms
"""

import time
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch
import pytest

from src.services.storage.session_storage_service import SessionStorageService
from src.services.memory_security_service import MemorySecurityService
from src.models.session import Session


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
    import uuid
    from datetime import datetime
    return Session(
        id=str(uuid.uuid4()),
        username="testuser",
        derived_key=b"0123456789abcdef" * 2  # 32 bytes
    )


class TestSessionPerformance:
    """Test session operation performance requirements."""
    
    def test_session_validation_performance(self, storage_service, sample_session):
        """Test that session validation completes in under 10ms."""
        # First persist a session
        storage_service.persist_session(sample_session)
        
        # Time the load operation (validation)
        start_time = time.perf_counter()
        loaded_session = storage_service.load_session()
        end_time = time.perf_counter()
        
        duration_ms = (end_time - start_time) * 1000
        
        assert loaded_session is not None, "Session should load successfully"
        assert duration_ms < 10, f"Session validation took {duration_ms:.2f}ms, should be < 10ms"
        
        print(f"Session validation took: {duration_ms:.2f}ms")
    
    def test_session_persistence_performance(self, storage_service, sample_session):
        """Test that session persistence completes in reasonable time."""
        # Time the persist operation
        start_time = time.perf_counter()
        result = storage_service.persist_session(sample_session)
        end_time = time.perf_counter()
        
        duration_ms = (end_time - start_time) * 1000
        
        assert result is not None, "Session should persist successfully"
        assert duration_ms < 50, f"Session persistence took {duration_ms:.2f}ms, should be < 50ms"
        
        print(f"Session persistence took: {duration_ms:.2f}ms")
    
    def test_memory_clearing_performance(self):
        """Test that memory clearing completes in under 1ms."""
        memory_service = MemorySecurityService()
        
        # Create sensitive data
        sensitive_data = bytearray(b"sensitive_password_123" * 10)  # ~230 bytes
        
        # Time the clear operation
        start_time = time.perf_counter()
        memory_service.secure_clear(sensitive_data)
        end_time = time.perf_counter()
        
        duration_ms = (end_time - start_time) * 1000
        
        assert all(byte == 0 for byte in sensitive_data), "Memory should be cleared"
        assert duration_ms < 1, f"Memory clearing took {duration_ms:.2f}ms, should be < 1ms"
        
        print(f"Memory clearing took: {duration_ms:.2f}ms")
    
    def test_large_memory_clearing_performance(self):
        """Test memory clearing performance with larger data."""
        memory_service = MemorySecurityService()
        
        # Create larger sensitive data (1KB)
        sensitive_data = bytearray(b"X" * 1024)
        
        # Time the clear operation
        start_time = time.perf_counter()
        memory_service.secure_clear(sensitive_data)
        end_time = time.perf_counter()
        
        duration_ms = (end_time - start_time) * 1000
        
        assert all(byte == 0 for byte in sensitive_data), "Memory should be cleared"
        assert duration_ms < 5, f"Large memory clearing took {duration_ms:.2f}ms, should be < 5ms"
        
        print(f"Large memory clearing (1KB) took: {duration_ms:.2f}ms")
    
    def test_session_context_manager_performance(self):
        """Test performance of secure memory context manager."""
        memory_service = MemorySecurityService()
        
        # Time the context manager usage
        start_time = time.perf_counter()
        
        with memory_service.secure_memory(initial_size=256) as secure_data:
            secure_data[:10] = b"test_data!"
            # Context manager should clear on exit
        
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        
        assert all(byte == 0 for byte in secure_data), "Memory should be cleared"
        assert duration_ms < 2, f"Secure context manager took {duration_ms:.2f}ms, should be < 2ms"
        
        print(f"Secure context manager took: {duration_ms:.2f}ms")
    
    def test_multiple_session_operations_performance(self, storage_service):
        """Test performance of multiple session operations."""
        import uuid
        
        # Create multiple sessions
        sessions = [
            Session(id=str(uuid.uuid4()), username=f"user{i}", derived_key=b"key" * 8)
            for i in range(5)
        ]
        
        # Time multiple persist operations
        start_time = time.perf_counter()
        
        for session in sessions:
            storage_service.persist_session(session)
        
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        
        # Should complete all operations in reasonable time
        assert duration_ms < 200, f"Multiple session operations took {duration_ms:.2f}ms, should be < 200ms"
        
        print(f"5 session operations took: {duration_ms:.2f}ms ({duration_ms/5:.2f}ms each)")
    
    def test_encryption_performance(self, storage_service):
        """Test encryption/decryption performance."""
        import uuid
        
        session = Session(
            id=str(uuid.uuid4()),
            username="performance_test_user",
            derived_key=b"performance_test_key" + b"0" * 16  # 32 bytes total
        )
        
        # Time encryption (persist)
        start_time = time.perf_counter()
        result = storage_service.persist_session(session)
        persist_time = time.perf_counter() - start_time
        
        # Time decryption (load)
        start_time = time.perf_counter()
        loaded_session = storage_service.load_session()
        load_time = time.perf_counter() - start_time
        
        persist_ms = persist_time * 1000
        load_ms = load_time * 1000
        
        assert result is not None, "Session should persist"
        assert loaded_session is not None, "Session should load"
        assert persist_ms < 25, f"Encryption took {persist_ms:.2f}ms, should be < 25ms"
        assert load_ms < 25, f"Decryption took {load_ms:.2f}ms, should be < 25ms"
        
        print(f"Encryption: {persist_ms:.2f}ms, Decryption: {load_ms:.2f}ms")


if __name__ == "__main__":
    # Run performance tests directly
    pytest.main([__file__, "-v", "-s"])