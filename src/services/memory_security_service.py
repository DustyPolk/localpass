"""Memory Security Service.

Handles secure clearing of sensitive data from memory.
"""
import os
from typing import Union, ContextManager
from contextlib import contextmanager
from src.config.session_config import SECURE_MEMORY_WIPE_PASSES


class MemorySecurityService:
    """Service for secure memory handling."""
    
    def __init__(self):
        """Initialize memory security service."""
        pass
    
    def secure_clear(self, data: Union[bytearray, memoryview]) -> None:
        """Securely clear sensitive data from memory.
        
        Args:
            data: bytearray or memoryview to clear
            
        Note:
            This performs multiple overwrite passes to make data recovery difficult.
        """
        if data is None:
            return
        
        if not isinstance(data, (bytearray, memoryview)):
            raise TypeError("Data must be bytearray or memoryview")
        
        # Get the underlying buffer
        if isinstance(data, memoryview):
            if not data.readonly:
                buffer = data
            else:
                # Can't clear readonly memoryview
                return
        else:
            buffer = data
        
        # Perform multiple overwrite passes
        for pass_num in range(SECURE_MEMORY_WIPE_PASSES):
            if pass_num == 0:
                # First pass: all zeros
                pattern = 0x00
            elif pass_num == 1:
                # Second pass: all ones
                pattern = 0xFF
            else:
                # Additional passes: alternating patterns
                pattern = 0xAA if pass_num % 2 == 0 else 0x55
            
            # Overwrite the entire buffer
            for i in range(len(buffer)):
                buffer[i] = pattern
        
        # Final pass: ensure everything ends up as zero
        for i in range(len(buffer)):
            buffer[i] = 0x00
    
    @contextmanager
    def secure_memory(self, initial_data: bytes = None) -> ContextManager[bytearray]:
        """Context manager for secure memory that auto-clears on exit.
        
        Args:
            initial_data: Optional initial data to store
            
        Yields:
            bytearray that will be securely cleared on exit
            
        Example:
            with memory_service.secure_memory(b"secret") as secure_data:
                # Use secure_data
                pass
            # secure_data is automatically cleared here
        """
        if initial_data is None:
            secure_data = bytearray()
        else:
            secure_data = bytearray(initial_data)
        
        try:
            yield secure_data
        finally:
            self.secure_clear(secure_data)
    
    def lock_memory(self, data: Union[bytearray, memoryview]) -> bool:
        """Attempt to lock memory pages to prevent swapping (best effort).
        
        Args:
            data: Data to lock in memory
            
        Returns:
            True if locking succeeded, False otherwise
            
        Note:
            This is a best-effort operation that may fail due to permissions
            or platform limitations.
        """
        try:
            # Try to use mlock on Unix systems
            if hasattr(os, 'mlock'):
                # Get memory address and size
                if isinstance(data, memoryview):
                    # Can't easily get address of memoryview
                    return False
                
                # This is a simplified approach - real implementation would need
                # to get the actual memory address of the bytearray
                # For now, just return False as we can't easily implement this
                return False
            else:
                # Not supported on this platform
                return False
                
        except (OSError, PermissionError):
            # Insufficient privileges or other error
            return False
    
    def unlock_memory(self, data: Union[bytearray, memoryview]) -> bool:
        """Unlock previously locked memory pages.
        
        Args:
            data: Data to unlock
            
        Returns:
            True if unlocking succeeded, False otherwise
        """
        try:
            # Try to use munlock on Unix systems
            if hasattr(os, 'munlock'):
                # Similar limitations as lock_memory
                return False
            else:
                return False
                
        except (OSError, PermissionError):
            return False
    
    def create_secure_buffer(self, size: int) -> bytearray:
        """Create a secure buffer of specified size.
        
        Args:
            size: Size of buffer in bytes
            
        Returns:
            bytearray initialized with zeros
        """
        if size < 0:
            raise ValueError("Size must be non-negative")
        
        buffer = bytearray(size)
        
        # Try to lock the memory (best effort)
        self.lock_memory(buffer)
        
        return buffer
    
    def copy_secure(self, source: bytes, dest: bytearray) -> None:
        """Securely copy data between buffers.
        
        Args:
            source: Source data to copy
            dest: Destination buffer
            
        Raises:
            ValueError: If destination is too small
        """
        if len(source) > len(dest):
            raise ValueError("Destination buffer too small")
        
        # Clear destination first
        self.secure_clear(dest)
        
        # Copy data
        for i, byte in enumerate(source):
            dest[i] = byte
    
    def compare_secure(self, data1: Union[bytes, bytearray], data2: Union[bytes, bytearray]) -> bool:
        """Securely compare two data buffers (constant time).
        
        Args:
            data1: First data buffer
            data2: Second data buffer
            
        Returns:
            True if buffers are equal, False otherwise
            
        Note:
            This comparison takes constant time regardless of where the
            difference occurs, preventing timing attacks.
        """
        if len(data1) != len(data2):
            return False
        
        result = 0
        for b1, b2 in zip(data1, data2):
            result |= b1 ^ b2
        
        return result == 0
    
    def generate_random_bytes(self, size: int) -> bytearray:
        """Generate cryptographically secure random bytes.
        
        Args:
            size: Number of bytes to generate
            
        Returns:
            bytearray with random data
        """
        if size < 0:
            raise ValueError("Size must be non-negative")
        
        random_data = os.urandom(size)
        return bytearray(random_data)