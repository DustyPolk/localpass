"""Authentication Service.

Handles master password authentication and credential management.
"""
import json
from datetime import datetime
from typing import Optional, Tuple
from src.models.master_credential import MasterCredential
from src.models.session import Session
from src.services.database_service import DatabaseService
from src.services.master_password_service import MasterPasswordService
from src.services.key_derivation_service import KeyDerivationService
from src.services.session_service import SessionService


class AuthenticationService:
    """Service for authentication and credential management."""
    
    def __init__(self, database_service: Optional[DatabaseService] = None):
        """Initialize authentication service.
        
        Args:
            database_service: Database service instance (creates new if None)
        """
        self.db_service = database_service or DatabaseService()
        self.master_service = MasterPasswordService()
        self.key_service = KeyDerivationService()
        self.session_service = SessionService()
    
    def authenticate(self, password: str, timeout_minutes: int = 15) -> Tuple[bool, Optional[Session], Optional[str]]:
        """Authenticate user with master password and create session.
        
        Args:
            password: Master password to authenticate with
            timeout_minutes: Session timeout in minutes
            
        Returns:
            Tuple of (success: bool, session: Optional[Session], error_message: Optional[str])
        """
        try:
            # Get master credential from database
            master_cred = self._get_master_credential()
            if not master_cred:
                return False, None, "Password manager not initialized"
            
            # Check if account is locked
            if master_cred.is_locked():
                return False, None, f"Account locked until {master_cred.locked_until.strftime('%H:%M:%S')}"
            
            # Verify master password
            is_valid = self.master_service.verify_master_password(password, master_cred.password_hash)
            
            if not is_valid:
                # Increment failure count and update database
                master_cred.increment_failure_count()
                self._update_master_credential(master_cred)
                
                remaining_attempts = max(0, 5 - master_cred.auth_failure_count)
                if master_cred.is_locked():
                    return False, None, "Too many failed attempts. Account locked for 15 minutes."
                else:
                    return False, None, f"Invalid password. {remaining_attempts} attempts remaining."
            
            # Authentication successful - reset failure count
            master_cred.reset_failure_count()
            self._update_master_credential(master_cred)
            
            # Derive database encryption key
            database_key, _ = self.key_service.derive_database_key(
                password, 
                master_cred.get_key_derivation_salt()
            )
            
            # Create authenticated session
            session = self.session_service.create_session(
                username=master_cred.username,
                derived_key=database_key,
                idle_timeout=timeout_minutes
            )
            
            return True, session, None
            
        except Exception as e:
            return False, None, f"Authentication error: {e}"
    
    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate an active session.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            Valid session or None if expired/invalid
        """
        return self.session_service.validate_session(session_id)
    
    def logout(self, session_id: str) -> bool:
        """Logout user and terminate session.
        
        Args:
            session_id: Session ID to terminate
            
        Returns:
            True if session was terminated
        """
        return self.session_service.terminate_session(session_id)
    
    def logout_user(self, username: str) -> int:
        """Logout all sessions for a user.
        
        Args:
            username: Username to logout
            
        Returns:
            Number of sessions terminated
        """
        return self.session_service.terminate_user_sessions(username)
    
    def check_session_status(self, session_id: str) -> dict:
        """Check status of a session.
        
        Args:
            session_id: Session ID to check
            
        Returns:
            Dictionary with session status information
        """
        session_info = self.session_service.get_session_info(session_id)
        
        if not session_info:
            return {
                'status': 'invalid',
                'message': 'Session not found or expired',
                'is_active': False
            }
        
        return {
            'status': 'active',
            'message': f"Session expires in {session_info['remaining_minutes']} minutes",
            'is_active': True,
            'username': session_info['username'],
            'remaining_minutes': session_info['remaining_minutes'],
            'expires_at': session_info['expires_at']
        }
    
    def extend_session(self, session_id: str, additional_minutes: int = None) -> bool:
        """Extend session timeout.
        
        Args:
            session_id: Session to extend
            additional_minutes: Additional minutes (None to reset to full timeout)
            
        Returns:
            True if session was extended
        """
        return self.session_service.extend_session(session_id, additional_minutes)
    
    def get_master_credential_info(self) -> Optional[dict]:
        """Get non-sensitive master credential information.
        
        Returns:
            Dictionary with master credential info or None if not initialized
        """
        try:
            master_cred = self._get_master_credential()
            if not master_cred:
                return None
            
            return {
                'username': master_cred.username,
                'created_at': master_cred.created_at.isoformat(),
                'last_auth_at': master_cred.last_auth_at.isoformat() if master_cred.last_auth_at else None,
                'auth_failure_count': master_cred.auth_failure_count,
                'is_locked': master_cred.is_locked(),
                'locked_until': master_cred.locked_until.isoformat() if master_cred.locked_until else None,
                'key_derivation_algorithm': master_cred.key_derivation_params.get('algorithm'),
                'pbkdf2_iterations': master_cred.key_derivation_params.get('iterations')
            }
            
        except Exception:
            return None
    
    def change_master_password(self, current_password: str, new_password: str) -> Tuple[bool, Optional[str]]:
        """Change the master password.
        
        Args:
            current_password: Current master password
            new_password: New master password
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            # First authenticate with current password
            is_valid, _, error_msg = self.authenticate(current_password, 1)  # 1 minute temp session
            
            if not is_valid:
                return False, error_msg
            
            # Get current master credential
            master_cred = self._get_master_credential()
            if not master_cred:
                return False, "Master credential not found"
            
            # Generate new password hash
            new_hash = self.master_service.hash_master_password(new_password)
            
            # Generate new salt for key derivation
            new_salt = self.key_service.generate_salt(32)
            
            # Update master credential
            master_cred.password_hash = new_hash
            master_cred.salt = new_salt
            master_cred.reset_failure_count()  # Reset any previous failures
            
            # Update in database
            self._update_master_credential(master_cred)
            
            # Terminate all existing sessions (password changed)
            self.session_service.terminate_user_sessions(master_cred.username)
            
            return True, None
            
        except Exception as e:
            return False, f"Password change failed: {e}"
    
    def _get_master_credential(self) -> Optional[MasterCredential]:
        """Get master credential from database.
        
        Returns:
            MasterCredential instance or None if not found
        """
        try:
            conn = self.db_service.connect()
            cursor = conn.execute('SELECT * FROM master_credential WHERE id = 1')
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return MasterCredential.from_database_row(row)
            
        except Exception:
            return None
    
    def _update_master_credential(self, master_cred: MasterCredential) -> bool:
        """Update master credential in database.
        
        Args:
            master_cred: Master credential to update
            
        Returns:
            True if update was successful
        """
        try:
            conn = self.db_service.connect()
            conn.execute('''
                UPDATE master_credential SET
                    password_hash = ?,
                    salt = ?,
                    key_derivation_params = ?,
                    last_auth_at = ?,
                    auth_failure_count = ?,
                    locked_until = ?
                WHERE id = 1
            ''', (
                master_cred.password_hash,
                master_cred.salt,
                json.dumps(master_cred.key_derivation_params),
                master_cred.last_auth_at.isoformat() if master_cred.last_auth_at else None,
                master_cred.auth_failure_count,
                master_cred.locked_until.isoformat() if master_cred.locked_until else None
            ))
            conn.commit()
            return True
            
        except Exception:
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        return self.session_service.cleanup_expired_sessions()
    
    def get_authentication_stats(self) -> dict:
        """Get authentication service statistics.
        
        Returns:
            Dictionary with authentication statistics
        """
        session_stats = self.session_service.get_stats()
        master_info = self.get_master_credential_info()
        
        return {
            'session_stats': session_stats,
            'master_credential': {
                'initialized': master_info is not None,
                'username': master_info.get('username') if master_info else None,
                'is_locked': master_info.get('is_locked', False) if master_info else False,
                'failure_count': master_info.get('auth_failure_count', 0) if master_info else 0
            },
            'database_connected': self.db_service.database_exists()
        }