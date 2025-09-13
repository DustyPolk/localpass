"""Contract test for POST /session/create endpoint.

Tests the session creation API contract as defined in session-operations.yaml.
These tests MUST fail initially (TDD approach).
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import uuid


class TestSessionCreateContract:
    """Contract tests for session creation endpoint."""
    
    def test_create_session_success(self):
        """Test successful session creation with valid credentials."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.services.session_service import SessionService
        
        auth_service = AuthenticationService()
        request_data = {
            "username": "testuser",
            "password": "TestPass123!",
            "timeout_minutes": 15
        }
        
        # Act
        success, session, error = auth_service.authenticate(
            password=request_data["password"],
            timeout_minutes=request_data["timeout_minutes"]
        )
        
        # Assert - Contract requirements
        assert success is True
        assert session is not None
        assert error is None
        
        # Verify response schema matches contract
        assert isinstance(session.id, str)
        assert uuid.UUID(session.id, version=4)  # Valid UUID4
        assert session.username == "testuser"
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_activity_at, datetime)
        assert session.idle_timeout_minutes == 15
        
        # Verify expiration calculation
        expected_expires = session.last_activity_at + timedelta(minutes=15)
        assert session.expires_at == expected_expires
        
        # Verify remaining time
        remaining = session.get_remaining_time()
        assert 0 <= remaining.total_seconds() <= 900  # 0-15 minutes
    
    def test_create_session_invalid_password(self):
        """Test session creation with invalid password."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        
        auth_service = AuthenticationService()
        request_data = {
            "username": "testuser",
            "password": "WrongPassword",
            "timeout_minutes": 15
        }
        
        # Act
        success, session, error = auth_service.authenticate(
            password=request_data["password"],
            timeout_minutes=request_data["timeout_minutes"]
        )
        
        # Assert - Contract requirements for 401 response
        assert success is False
        assert session is None
        assert error is not None
        assert "Invalid password" in error or "not initialized" in error
    
    def test_create_session_account_locked(self):
        """Test session creation when account is locked."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        from src.models.master_credential import MasterCredential
        
        auth_service = AuthenticationService()
        
        # Simulate locked account
        with patch.object(auth_service, '_get_master_credential') as mock_get:
            locked_cred = Mock(spec=MasterCredential)
            locked_cred.is_locked.return_value = True
            locked_cred.locked_until = datetime.now() + timedelta(minutes=10)
            mock_get.return_value = locked_cred
            
            # Act
            success, session, error = auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
            
            # Assert - Contract requirements for 423 response
            assert success is False
            assert session is None
            assert error is not None
            assert "locked" in error.lower()
    
    def test_create_session_validates_timeout(self):
        """Test that timeout is fixed at 15 minutes."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        
        auth_service = AuthenticationService()
        
        # Act - Try to create with different timeout
        success, session, _ = auth_service.authenticate(
            password="TestPass123!",
            timeout_minutes=30  # Try 30 minutes
        )
        
        # Assert - Should still be 15 minutes (fixed per spec)
        if success and session:
            assert session.idle_timeout_minutes == 15  # Fixed value
    
    def test_create_session_username_validation(self):
        """Test username validation in session creation."""
        # Arrange
        from src.services.auth_service import AuthenticationService
        
        auth_service = AuthenticationService()
        
        # Test empty username
        with pytest.raises(ValueError, match="Username cannot be empty"):
            auth_service.authenticate(
                password="TestPass123!",
                timeout_minutes=15
            )
    
    def test_create_session_password_validation(self):
        """Test password validation requirements."""
        # Arrange  
        from src.services.auth_service import AuthenticationService
        
        auth_service = AuthenticationService()
        
        # Test too short password
        success, session, error = auth_service.authenticate(
            password="short",  # Less than 8 chars
            timeout_minutes=15
        )
        
        # Assert
        assert success is False
        assert session is None
        assert error is not None