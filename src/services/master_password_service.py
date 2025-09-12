"""Master Password Service.

Handles master password hashing and verification using Argon2id.
Implements the security interface contract for master password operations.
"""
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError, InvalidHashError


class MasterPasswordService:
    """Service for master password hashing and verification."""
    
    def __init__(self):
        """Initialize master password service with high-security parameters."""
        # High-security parameters for password managers (vs web apps)
        self.hasher = PasswordHasher(
            time_cost=8,        # Higher than web apps (2-4) 
            memory_cost=102400, # 100MB+ for password managers
            parallelism=8,      # Use available cores
            hash_len=32,        # 256-bit hash
            salt_len=32         # 256-bit salt
        )
    
    def hash_master_password(self, password: str) -> str:
        """Hash a master password for secure storage.
        
        Args:
            password: Master password (8-128 characters, UTF-8 encoded)
            
        Returns:
            Argon2id hash string (always 97 characters)
            
        Raises:
            ValueError: If password length is invalid or contains invalid UTF-8
            SystemError: If insufficient memory for hashing
        """
        # Validate password length
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        if len(password) > 128:
            raise ValueError("Password must be no more than 128 characters long")
        
        # Validate UTF-8 encoding
        try:
            password.encode('utf-8')
        except UnicodeEncodeError as e:
            raise ValueError(f"Password contains invalid UTF-8: {e}")
        
        try:
            # Hash the password with Argon2id
            hash_string = self.hasher.hash(password)
            
            # Verify the hash format and length
            if not hash_string.startswith('$argon2id$'):
                raise SystemError("Generated hash has invalid format")
            
            if len(hash_string) < 97:
                raise SystemError(f"Generated hash is too short: {len(hash_string)}")
            
            return hash_string
            
        except HashingError as e:
            raise SystemError(f"Hashing failed: {e}")
        except MemoryError:
            raise SystemError("Insufficient memory for password hashing")
    
    def verify_master_password(self, password: str, hash_string: str) -> bool:
        """Verify a password against stored hash using constant-time comparison.
        
        Args:
            password: Candidate password to verify
            hash_string: Stored Argon2id hash string
            
        Returns:
            True if password matches hash, False otherwise
            
        Raises:
            ValueError: If hash string is malformed
        """
        if not isinstance(password, str):
            return False
        
        if not isinstance(hash_string, str):
            raise ValueError("Hash string must be a string")
        
        # Validate hash format
        if not hash_string.startswith('$argon2id$'):
            raise ValueError("Malformed hash: must start with $argon2id$")
        
        # Count dollar signs to validate format: $argon2id$v=19$m=X,t=Y,p=Z$salt$hash
        if hash_string.count('$') != 5:
            raise ValueError("Malformed hash: invalid format structure")
        
        try:
            # Verify password against hash (uses constant-time comparison internally)
            self.hasher.verify(hash_string, password)
            return True
            
        except VerifyMismatchError:
            # Password doesn't match - this is expected for wrong passwords
            return False
            
        except InvalidHashError as e:
            # Hash is malformed or corrupted
            raise ValueError(f"Malformed hash: {e}")
        
        except Exception:
            # Any other error should return False rather than crash
            return False
    
    def needs_rehash(self, hash_string: str) -> bool:
        """Check if a hash needs to be updated due to changed parameters.
        
        Args:
            hash_string: Existing Argon2id hash string
            
        Returns:
            True if hash should be regenerated with current parameters
        """
        try:
            return self.hasher.check_needs_rehash(hash_string)
        except:
            # If we can't check, assume it needs rehashing
            return True
    
    def get_hash_info(self, hash_string: str) -> dict:
        """Extract information from an Argon2id hash string.
        
        Args:
            hash_string: Argon2id hash to analyze
            
        Returns:
            Dictionary containing hash parameters
            
        Raises:
            ValueError: If hash string is malformed
        """
        if not hash_string.startswith('$argon2id$'):
            raise ValueError("Not an Argon2id hash")
        
        try:
            parts = hash_string.split('$')
            if len(parts) != 6:
                raise ValueError("Invalid hash format")
            
            algorithm = parts[1]
            version = parts[2]
            params_str = parts[3]
            
            # Parse parameters
            params = {}
            for param in params_str.split(','):
                key, value = param.split('=')
                params[key] = int(value)
            
            return {
                'algorithm': algorithm,
                'version': version,
                'memory_cost': params.get('m', 0),
                'time_cost': params.get('t', 0),
                'parallelism': params.get('p', 0),
                'hash_length': len(parts[5]),
                'salt_length': len(parts[4]),
                'total_length': len(hash_string)
            }
            
        except (ValueError, IndexError) as e:
            raise ValueError(f"Failed to parse hash: {e}")
    
    def get_current_parameters(self) -> dict:
        """Get current hashing parameters.
        
        Returns:
            Dictionary containing current Argon2id parameters
        """
        return {
            'time_cost': self.hasher.time_cost,
            'memory_cost': self.hasher.memory_cost,
            'parallelism': self.hasher.parallelism,
            'hash_len': self.hasher.hash_len,
            'salt_len': self.hasher.salt_len,
            'encoding': self.hasher.encoding
        }