"""Unit tests for MemorySecurityService."""

import pytest
from unittest.mock import patch, MagicMock
import gc

from src.services.memory_security_service import MemorySecurityService


class TestMemorySecurityService:
    """Test MemorySecurityService functionality."""
    
    def test_secure_clear_bytearray(self):
        """Test that secure_clear zeros out bytearray."""
        service = MemorySecurityService()
        
        # Create sensitive data
        sensitive_data = bytearray(b"sensitive_password_123")
        original_length = len(sensitive_data)
        
        # Clear the data
        service.secure_clear(sensitive_data)
        
        # Verify data is zeroed
        assert len(sensitive_data) == original_length
        assert all(byte == 0 for byte in sensitive_data)
    
    def test_secure_clear_bytes(self):
        """Test that secure_clear handles bytes by converting to bytearray."""
        service = MemorySecurityService()
        
        # Create bytes data
        sensitive_bytes = b"sensitive_data"
        
        # Clear should work (internally converts to bytearray)
        result = service.secure_clear(sensitive_bytes)
        
        # Should return True (operation completed)
        assert result is True
    
    def test_secure_clear_string(self):
        """Test that secure_clear handles string by encoding to bytearray."""
        service = MemorySecurityService()
        
        # Create string data
        sensitive_string = "sensitive_password"
        
        # Clear should work (internally converts to bytearray)
        result = service.secure_clear(sensitive_string)
        
        # Should return True (operation completed)
        assert result is True
    
    def test_secure_clear_none(self):
        """Test that secure_clear handles None gracefully."""
        service = MemorySecurityService()
        
        result = service.secure_clear(None)
        
        assert result is True  # Should not raise exception
    
    def test_secure_clear_empty_data(self):
        """Test that secure_clear handles empty data."""
        service = MemorySecurityService()
        
        empty_bytearray = bytearray()
        result = service.secure_clear(empty_bytearray)
        
        assert result is True
        assert len(empty_bytearray) == 0
    
    def test_secure_clear_multiple_overwrites(self):
        """Test that secure_clear performs multiple overwrite passes."""
        service = MemorySecurityService()
        
        # Create data to clear
        data = bytearray(b"test_data_123")
        
        # Mock the overwrite operations to verify they happen
        with patch.object(service, '_overwrite_with_pattern') as mock_overwrite:
            service.secure_clear(data)
            
            # Should have been called multiple times (3 passes)
            assert mock_overwrite.call_count == 3
    
    def test_overwrite_with_pattern(self):
        """Test the internal overwrite pattern method."""
        service = MemorySecurityService()
        
        # Create test data
        data = bytearray(b"original_data")
        original_length = len(data)
        
        # Overwrite with specific pattern
        service._overwrite_with_pattern(data, 0xAA)
        
        # Verify all bytes are the pattern
        assert len(data) == original_length
        assert all(byte == 0xAA for byte in data)
    
    def test_secure_memory_context_manager(self):
        """Test secure_memory context manager."""
        service = MemorySecurityService()
        
        # Use context manager
        with service.secure_memory() as secure_data:
            # Add sensitive data
            secure_data.extend(b"password123")
            assert len(secure_data) == 11
            assert secure_data == bytearray(b"password123")
        
        # After context, data should be cleared
        assert all(byte == 0 for byte in secure_data)
    
    def test_secure_memory_context_manager_with_exception(self):
        """Test that secure_memory clears data even if exception occurs."""
        service = MemorySecurityService()
        
        try:
            with service.secure_memory() as secure_data:
                secure_data.extend(b"sensitive")
                # Simulate an exception
                raise ValueError("Test exception")
        except ValueError:
            pass  # Expected exception
        
        # Data should still be cleared despite exception
        assert all(byte == 0 for byte in secure_data)
    
    def test_secure_memory_with_initial_size(self):
        """Test secure_memory with initial size allocation."""
        service = MemorySecurityService()
        
        with service.secure_memory(initial_size=64) as secure_data:
            assert len(secure_data) == 64
            assert all(byte == 0 for byte in secure_data)
            
            # Use some of the allocated space
            secure_data[:8] = b"password"
        
        # Should be cleared after context
        assert all(byte == 0 for byte in secure_data)
    
    def test_force_garbage_collection(self):
        """Test that service can force garbage collection."""
        service = MemorySecurityService()
        
        # Mock gc.collect to verify it's called
        with patch('gc.collect') as mock_collect:
            service.force_garbage_collection()
            mock_collect.assert_called_once()
    
    def test_clear_multiple_data_types(self):
        """Test clearing multiple different data types."""
        service = MemorySecurityService()
        
        # Test different data types
        test_data = [
            bytearray(b"test1"),
            b"test2",
            "test3",
            bytearray(b"longer_test_data_string"),
            b"",  # Empty bytes
            bytearray(),  # Empty bytearray
        ]
        
        # Clear all data
        for data in test_data:
            result = service.secure_clear(data)
            assert result is True
    
    def test_secure_clear_large_data(self):
        """Test clearing large data efficiently."""
        service = MemorySecurityService()
        
        # Create large data (1MB)
        large_data = bytearray(b"X" * (1024 * 1024))
        
        # Clear should work efficiently
        result = service.secure_clear(large_data)
        
        assert result is True
        assert all(byte == 0 for byte in large_data)
    
    def test_concurrent_clearing(self):
        """Test that concurrent clearing operations work safely."""
        service = MemorySecurityService()
        
        # Create multiple data items
        data_items = [
            bytearray(f"data_{i}".encode()) for i in range(10)
        ]
        
        # Clear all items (simulating concurrent operations)
        results = []
        for data in data_items:
            result = service.secure_clear(data)
            results.append(result)
        
        # All operations should succeed
        assert all(results)
        
        # All data should be cleared
        for data in data_items:
            assert all(byte == 0 for byte in data)
    
    def test_memory_patterns_different(self):
        """Test that different overwrite patterns are used."""
        service = MemorySecurityService()
        
        # Track patterns used
        patterns_used = []
        
        def track_pattern(data, pattern):
            patterns_used.append(pattern)
            # Call original method
            for i in range(len(data)):
                data[i] = pattern
        
        with patch.object(service, '_overwrite_with_pattern', side_effect=track_pattern):
            data = bytearray(b"test")
            service.secure_clear(data)
        
        # Should use different patterns
        assert len(patterns_used) == 3
        assert len(set(patterns_used)) >= 2  # At least 2 different patterns
    
    def test_cleanup_method(self):
        """Test the cleanup method for explicit resource cleanup."""
        service = MemorySecurityService()
        
        # Create some data and context managers
        with service.secure_memory() as data1:
            data1.extend(b"test1")
        
        with service.secure_memory() as data2:
            data2.extend(b"test2")
        
        # Call cleanup
        with patch('gc.collect') as mock_collect:
            service.cleanup()
            mock_collect.assert_called_once()
    
    def test_service_as_context_manager(self):
        """Test using the service itself as a context manager."""
        # Test if service can be used as context manager for cleanup
        with MemorySecurityService() as service:
            with service.secure_memory() as data:
                data.extend(b"test_data")
                assert len(data) == 9
        
        # Data should be cleared after service context
        assert all(byte == 0 for byte in data)