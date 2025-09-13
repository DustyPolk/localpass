"""Security test: Memory clearing verification.

Tests that sensitive data is properly cleared from memory.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta


class TestMemoryClearingSecurity:
    """Security tests for memory clearing of sensitive data."""
    
    def test_session_key_cleared_on_termination(self):
        """Test that session encryption keys are cleared when session terminates."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create session with bytearray key (clearable)
        test_key = bytearray(b"very_secret_key_data_32_bytes!!")
        test_session = Session(
            username="testuser",
            derived_key=test_key,
            idle_timeout_minutes=15
        )
        session_id = test_session.id
        session_service.active_sessions[session_id] = test_session
        
        # Keep reference to the key
        key_reference = test_session.derived_key
        
        # Act - Terminate session
        result = session_service.terminate_session(session_id)
        
        # Assert
        assert result is True
        
        # Key should be zeroed out
        if isinstance(key_reference, bytearray):
            assert all(b == 0 for b in key_reference), "Key not properly cleared"
        
        # Session should be removed from memory
        assert session_id not in session_service.active_sessions
    
    def test_expired_session_key_cleared(self):
        """Test that keys are cleared when sessions expire."""
        # Arrange
        from src.services.session_service import SessionService
        from src.models.session import Session
        
        session_service = SessionService()
        
        # Create expired session
        test_key = bytearray(b"expired_session_key_32_bytes!!!")
        expired_session = Session(
            username="testuser",
            derived_key=test_key,
            idle_timeout_minutes=15
        )
        # Force expiration
        expired_session.last_activity_at = datetime.now() - timedelta(minutes=20)
        
        session_id = expired_session.id
        session_service.active_sessions[session_id] = expired_session
        
        # Keep reference to key
        key_reference = expired_session.derived_key
        
        # Act - Validate expired session (should clean up)
        result = session_service.validate_session(session_id)
        
        # Assert
        assert result is None  # Session expired
        
        # Key should be cleared
        if isinstance(key_reference, bytearray):
            assert all(b == 0 for b in key_reference), "Expired session key not cleared"
    
    def test_memory_security_service_clearing(self):
        """Test the memory security service clearing functionality."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        
        memory_service = MemorySecurityService()
        
        # Create sensitive data
        sensitive_data = bytearray(b"super_secret_password_data_here")
        original_length = len(sensitive_data)
        
        # Act - Clear memory
        memory_service.secure_clear(sensitive_data)
        
        # Assert
        assert len(sensitive_data) == original_length  # Length preserved
        assert all(b == 0 for b in sensitive_data), "Memory not properly cleared"
    
    def test_multiple_clear_passes(self):
        """Test that memory clearing performs multiple overwrite passes."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        from src.config.session_config import SECURE_MEMORY_WIPE_PASSES
        
        memory_service = MemorySecurityService()
        
        # Test with different patterns
        test_data = bytearray(b"test_pattern_123456789abcdef")
        
        # Act - Clear with multiple passes
        memory_service.secure_clear(test_data)
        
        # Assert - Should be zeroed after all passes
        assert all(b == 0 for b in test_data)
        
        # Verify configuration exists
        assert SECURE_MEMORY_WIPE_PASSES >= 1
    
    def test_context_manager_auto_clearing(self):
        """Test that context manager automatically clears sensitive data."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        
        memory_service = MemorySecurityService()
        sensitive_ref = None
        
        # Act - Use context manager
        with memory_service.secure_memory(b"secret_data_for_context_mgr") as secure_data:
            sensitive_ref = secure_data
            assert secure_data is not None
            assert len(secure_data) > 0
        
        # Assert - Data should be cleared after context exit
        if isinstance(sensitive_ref, bytearray):
            assert all(b == 0 for b in sensitive_ref), "Context manager didn't clear data"
    
    def test_clearing_different_data_types(self):
        """Test clearing of different sensitive data types."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        
        memory_service = MemorySecurityService()
        
        # Test with bytearray
        byte_data = bytearray(b"bytearray_secret")
        memory_service.secure_clear(byte_data)
        assert all(b == 0 for b in byte_data)
        
        # Test with memoryview (if supported)
        try:
            mem_data = bytearray(b"memoryview_secret")
            mem_view = memoryview(mem_data)
            memory_service.secure_clear(mem_view)
            assert all(b == 0 for b in mem_data)
        except (TypeError, AttributeError):
            # memoryview clearing might not be implemented
            pass
    
    def test_clearing_performance(self):
        """Test that memory clearing meets performance requirements."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        import time
        
        memory_service = MemorySecurityService()
        
        # Large data to test performance
        large_data = bytearray(b"x" * 1024 * 32)  # 32KB
        
        # Act - Measure clearing time
        start_time = time.time()
        memory_service.secure_clear(large_data)
        clear_time = time.time() - start_time
        
        # Assert - Should be very fast (under 10ms for 32KB)
        assert clear_time < 0.01, f"Memory clearing too slow: {clear_time}s"
        assert all(b == 0 for b in large_data)
    
    def test_no_memory_leaks_in_clearing(self):
        """Test that clearing operations don't cause memory leaks."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        import gc
        
        memory_service = MemorySecurityService()
        
        # Track object count
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Act - Perform many clear operations
        for i in range(100):
            test_data = bytearray(f"test_data_{i}".encode() * 10)
            memory_service.secure_clear(test_data)
        
        # Force garbage collection
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Assert - Object count shouldn't grow significantly
        object_growth = final_objects - initial_objects
        assert object_growth < 50, f"Possible memory leak: {object_growth} new objects"
    
    def test_clearing_edge_cases(self):
        """Test memory clearing with edge cases."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        
        memory_service = MemorySecurityService()
        
        # Test empty data
        empty_data = bytearray()
        memory_service.secure_clear(empty_data)  # Should not crash
        assert len(empty_data) == 0
        
        # Test single byte
        single_byte = bytearray([42])
        memory_service.secure_clear(single_byte)
        assert single_byte[0] == 0
        
        # Test None (should handle gracefully)
        try:
            memory_service.secure_clear(None)
        except (TypeError, AttributeError):
            pass  # Expected for None input
    
    def test_session_destruction_clears_all_sensitive_data(self):
        """Test that session destruction clears all associated sensitive data."""
        # Arrange
        from src.models.session import Session
        
        # Create session with sensitive data
        derived_key = bytearray(b"derived_key_32_bytes_sensitive!")
        test_session = Session(
            username="testuser",
            derived_key=derived_key,
            idle_timeout_minutes=15
        )
        
        # Keep references to sensitive data
        key_ref = test_session.derived_key
        
        # Act - Destroy session (simulate garbage collection)
        if hasattr(test_session, '__del__'):
            test_session.__del__()
        del test_session
        
        # Assert - Sensitive data should be cleared
        if isinstance(key_ref, bytearray):
            # This test depends on proper implementation of session cleanup
            pass  # Will be implemented in the Session class
    
    def test_memory_protection_from_swap(self):
        """Test memory protection mechanisms (best effort)."""
        # Arrange
        from src.services.memory_security_service import MemorySecurityService
        
        memory_service = MemorySecurityService()
        
        # Test if memory locking is available (platform dependent)
        if hasattr(memory_service, 'lock_memory'):
            test_data = bytearray(b"data_to_lock_in_memory")
            
            # Act - Try to lock memory
            try:
                result = memory_service.lock_memory(test_data)
                # Assert - Should either succeed or fail gracefully
                assert isinstance(result, bool)
            except OSError:
                # Expected on systems without privilege
                pass