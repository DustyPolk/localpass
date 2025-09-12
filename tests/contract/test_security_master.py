"""Contract tests for master password operations.

These tests verify the security interface contract for master password handling.
They MUST fail before implementation exists (TDD requirement).
"""
import pytest
from src.services.master_password_service import MasterPasswordService


class TestMasterPasswordServiceContract:
    """Test master password service follows the security interface contract."""

    def test_hash_master_password_basic(self):
        """Test hash_master_password produces Argon2id hash."""
        # This test MUST fail until implementation exists
        service = MasterPasswordService()
        
        password = "testpassword123"
        hash_string = service.hash_master_password(password)
        
        # Verify Argon2id format
        assert hash_string.startswith("$argon2id$")
        assert len(hash_string) >= 97  # Minimum Argon2id hash length (varies with parameters)
        assert hash_string.count("$") == 5  # Proper format: $argon2id$v=19$m=X,t=Y,p=Z$salt$hash

    def test_hash_master_password_unique_salts(self):
        """Test hash_master_password generates unique salts for same password."""
        service = MasterPasswordService()
        
        password = "samepassword123"
        hash1 = service.hash_master_password(password)
        hash2 = service.hash_master_password(password)
        
        # Should be different hashes due to unique salts
        assert hash1 != hash2
        
        # But both should be valid Argon2id hashes
        assert hash1.startswith("$argon2id$")
        assert hash2.startswith("$argon2id$")

    def test_hash_master_password_length_validation(self):
        """Test hash_master_password validates password length."""
        service = MasterPasswordService()
        
        # Too short
        with pytest.raises(ValueError, match="Password must be at least"):
            service.hash_master_password("short")
        
        # Too long  
        with pytest.raises(ValueError, match="Password must be"):
            service.hash_master_password("x" * 129)

    def test_hash_master_password_unicode_support(self):
        """Test hash_master_password handles Unicode characters."""
        service = MasterPasswordService()
        
        unicode_password = "pässwörd123🔐"
        hash_string = service.hash_master_password(unicode_password)
        
        assert hash_string.startswith("$argon2id$")
        assert len(hash_string) >= 97

    def test_verify_master_password_correct(self):
        """Test verify_master_password returns True for correct password."""
        service = MasterPasswordService()
        
        password = "testpassword123"
        hash_string = service.hash_master_password(password)
        
        # Verification should succeed
        assert service.verify_master_password(password, hash_string) is True

    def test_verify_master_password_incorrect(self):
        """Test verify_master_password returns False for incorrect password."""
        service = MasterPasswordService()
        
        password = "testpassword123"
        wrong_password = "wrongpassword123"
        hash_string = service.hash_master_password(password)
        
        # Verification should fail
        assert service.verify_master_password(wrong_password, hash_string) is False

    def test_verify_master_password_malformed_hash(self):
        """Test verify_master_password handles malformed hash strings."""
        service = MasterPasswordService()
        
        password = "testpassword123"
        malformed_hash = "not-a-valid-hash"
        
        with pytest.raises(ValueError, match="Malformed hash"):
            service.verify_master_password(password, malformed_hash)

    def test_verify_master_password_constant_time(self):
        """Test verify_master_password uses constant time comparison."""
        import time
        service = MasterPasswordService()
        
        password = "testpassword123"
        hash_string = service.hash_master_password(password)
        wrong_password = "wrongpassword123"
        
        # Time correct password verification
        start = time.time()
        service.verify_master_password(password, hash_string)
        correct_time = time.time() - start
        
        # Time incorrect password verification  
        start = time.time()
        service.verify_master_password(wrong_password, hash_string)
        incorrect_time = time.time() - start
        
        # Times should be similar (within 200ms tolerance for timing variations)
        # Note: Argon2 is inherently variable time due to memory operations
        time_diff = abs(correct_time - incorrect_time)
        assert time_diff < 0.2, f"Timing difference too large: {time_diff}s"

    def test_hash_parameters_security_standards(self):
        """Test hash uses current security parameters."""
        service = MasterPasswordService()
        
        password = "testpassword123"
        hash_string = service.hash_master_password(password)
        
        # Parse Argon2id parameters from hash
        parts = hash_string.split("$")
        assert parts[1] == "argon2id"  # Algorithm
        assert parts[2] == "v=19"  # Version
        
        params = dict(param.split("=") for param in parts[3].split(","))
        assert int(params["m"]) >= 102400  # Memory cost >= 100MB
        assert int(params["t"]) >= 8  # Time cost >= 8
        assert int(params["p"]) >= 8  # Parallelism >= 8

    def test_service_initialization(self):
        """Test MasterPasswordService initializes with proper configuration."""
        service = MasterPasswordService()
        
        # Should have proper hasher configuration
        assert hasattr(service, 'hasher')
        assert service.hasher.time_cost >= 8
        assert service.hasher.memory_cost >= 102400
        assert service.hasher.parallelism >= 8
        assert service.hasher.hash_len == 32
        assert service.hasher.salt_len == 32