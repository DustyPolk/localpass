"""Session Storage Service.

Handles persistent storage of sessions in encrypted files with proper security.
"""
import os
import stat
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from src.models.session import Session
from src.models.session_file import SessionFile
from src.config.session_config import (
    SESSION_FILE_NAME,
    SESSION_FILE_PERMISSIONS,
    APP_NAME,
    APP_AUTHOR
)

try:
    import platformdirs
except ImportError:
    # Fallback if platformdirs not available
    import os
    class platformdirs:
        @staticmethod
        def user_data_dir(app_name: str, app_author: str = None) -> str:
            if os.name == 'nt':
                return os.path.expandvars(r'%APPDATA%\{}'.format(app_name))
            elif os.name == 'posix':
                return os.path.expanduser(f'~/.local/share/{app_name}')
            else:
                return os.path.expanduser(f'~/.{app_name}')


class SessionStorageService:
    """Service for secure session file storage."""
    
    def __init__(self):
        """Initialize session storage service."""
        self.session_dir = self._get_session_directory()
        self._ensure_session_dir()
    
    def _get_session_directory(self) -> Path:
        """Get platform-specific session storage directory."""
        data_dir = platformdirs.user_data_dir(APP_NAME, APP_AUTHOR)
        return Path(data_dir)
    
    def _ensure_session_dir(self) -> None:
        """Ensure session directory exists with proper permissions."""
        if not self.session_dir.exists():
            self.session_dir.mkdir(parents=True, mode=0o700)
        else:
            # Ensure proper permissions on existing directory
            self.session_dir.chmod(0o700)
    
    def _get_session_file_path(self) -> Path:
        """Get the session file path."""
        return self.session_dir / SESSION_FILE_NAME
    
    def _get_encryption_key(self) -> bytes:
        """Derive encryption key for session files."""
        # Use a combination of user info and system info for key derivation
        # This provides some security while allowing decryption by the same user
        import getpass
        import platform
        
        user_info = getpass.getuser()
        system_info = platform.node()
        
        # Create a consistent salt from user/system info
        salt_data = f"{user_info}:{system_info}:localpass_session".encode()
        salt = hashes.Hash(hashes.SHA256())
        salt.update(salt_data)
        salt_bytes = salt.finalize()[:16]  # 16 bytes for salt
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        
        # Use a fixed password for now (in real implementation, could use system keyring)
        password = f"localpass_session_key_{user_info}".encode()
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        return key
    
    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt session data."""
        key = self._get_encryption_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode())
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt session data."""
        key = self._get_encryption_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data).decode()
    
    def _write_file_atomically(self, file_path: Path, data: bytes) -> None:
        """Write file atomically with proper permissions."""
        # Write to temporary file first
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=file_path.parent,
            delete=False,
            prefix=f".{file_path.name}.",
            suffix=".tmp"
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(data)
            
            # Set permissions on temp file
            tmp_path.chmod(SESSION_FILE_PERMISSIONS)
        
        # Atomic rename
        tmp_path.rename(file_path)
    
    def persist_session(self, session: Session) -> Dict[str, Any]:
        """Persist session to encrypted file."""
        try:
            # Convert session to storage format
            session_file = SessionFile.from_session(session)
            
            # Serialize to JSON
            json_data = session_file.to_json()
            
            # Encrypt the data
            encrypted_data = self._encrypt_data(json_data)
            
            # Get file path
            file_path = self._get_session_file_path()
            
            # Write atomically
            self._write_file_atomically(file_path, encrypted_data)
            
            return {
                'file_path': str(file_path.absolute()),
                'encrypted': True
            }
            
        except Exception as e:
            raise IOError(f"Failed to persist session: {e}")
    
    def load_session(self) -> Optional[Session]:
        """Load session from encrypted file."""
        file_path = self._get_session_file_path()
        
        if not file_path.exists():
            return None
        
        try:
            # Read encrypted data
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            json_data = self._decrypt_data(encrypted_data)
            
            # Parse SessionFile
            session_file = SessionFile.from_json(json_data)
            
            # Check if expired
            if session_file.is_expired():
                # Clean up expired session
                self.delete_session()
                return None
            
            # Convert back to Session
            session = session_file.to_session()
            
            return session
            
        except Exception as e:
            # If we can't decrypt/parse, clean up the file
            try:
                file_path.unlink()
            except:
                pass
            return None
    
    def delete_session(self) -> bool:
        """Delete persisted session file."""
        file_path = self._get_session_file_path()
        
        if file_path.exists():
            try:
                file_path.unlink()
                return True
            except Exception:
                return False
        
        return True  # Nothing to delete
    
    def session_exists(self) -> bool:
        """Check if a session file exists."""
        return self._get_session_file_path().exists()
    
    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """Get basic info about stored session without full loading."""
        file_path = self._get_session_file_path()
        
        if not file_path.exists():
            return None
        
        try:
            stat_info = file_path.stat()
            return {
                'file_path': str(file_path.absolute()),
                'size': stat_info.st_size,
                'modified': stat_info.st_mtime,
                'permissions': oct(stat.S_IMODE(stat_info.st_mode))
            }
        except Exception:
            return None