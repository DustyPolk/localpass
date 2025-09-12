"""Encryption Service.

Handles AES-256-GCM encryption and decryption for password storage.
Implements the security interface contract for encryption operations.
"""
import json
import base64
import secrets
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class EncryptionService:
    """Service for AES-256-GCM encryption and decryption operations."""
    
    def __init__(self):
        """Initialize encryption service."""
        self.algorithm_name = "AES-256-GCM"
        self.key_length = 32  # 256 bits
        self.nonce_length = 12  # 96 bits (recommended for GCM)
        
    def encrypt_password(self, plaintext: str, key: bytes) -> str:
        """Encrypt password data with authenticated encryption.
        
        Args:
            plaintext: Password text (1-1024 characters)
            key: 32-byte AES-256 key
            
        Returns:
            JSON string containing encrypted data with nonce, ciphertext, and auth tag
            
        Raises:
            ValueError: If plaintext or key parameters are invalid
            EncryptionError: If GCM encryption fails
        """
        # Validate plaintext
        if not isinstance(plaintext, str):
            raise ValueError("Plaintext must be a string")
        
        if not (1 <= len(plaintext) <= 1024):
            raise ValueError("Plaintext must be between 1 and 1024 characters")
        
        # Validate key
        if not isinstance(key, bytes) or len(key) != self.key_length:
            raise ValueError("Key must be exactly 32 bytes for AES-256")
        
        try:
            # Generate unique nonce for this encryption
            nonce = secrets.token_bytes(self.nonce_length)
            
            # Initialize AES-GCM cipher
            aesgcm = AESGCM(key)
            
            # Encrypt with authentication
            plaintext_bytes = plaintext.encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
            
            # Split ciphertext and authentication tag
            # In AESGCM, the tag is appended to the ciphertext
            auth_tag = ciphertext[-16:]  # GCM tag is always 16 bytes
            ciphertext_only = ciphertext[:-16]
            
            # Create JSON structure
            encrypted_data = {
                "nonce": base64.b64encode(nonce).decode('ascii'),
                "ciphertext": base64.b64encode(ciphertext_only).decode('ascii'),
                "tag": base64.b64encode(auth_tag).decode('ascii'),
                "algorithm": self.algorithm_name
            }
            
            return json.dumps(encrypted_data, separators=(',', ':'))  # Compact JSON
            
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise EncryptionError(f"Encryption failed: {e}")
    
    def decrypt_password(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt and verify password data.
        
        Args:
            encrypted_data: JSON string from encrypt_password
            key: 32-byte AES-256 key
            
        Returns:
            Decrypted password string
            
        Raises:
            ValueError: If encrypted data or key parameters are invalid
            DecryptionError: If authentication fails or decryption fails
            IntegrityError: If data corruption is detected
        """
        # Validate key
        if not isinstance(key, bytes) or len(key) != self.key_length:
            raise ValueError("Key must be exactly 32 bytes for AES-256")
        
        # Validate and parse encrypted data
        if not isinstance(encrypted_data, str):
            raise ValueError("Encrypted data must be a string")
        
        try:
            data = json.loads(encrypted_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Encrypted data is not valid JSON: {e}")
        
        # Verify required fields
        required_fields = {'nonce', 'ciphertext', 'tag'}
        if not all(field in data for field in required_fields):
            raise ValueError("Encrypted data missing required fields")
        
        # Verify algorithm
        if data.get('algorithm') != self.algorithm_name:
            raise ValueError(f"Unsupported algorithm: {data.get('algorithm')}")
        
        try:
            # Decode base64 components
            nonce = base64.b64decode(data['nonce'])
            ciphertext_only = base64.b64decode(data['ciphertext'])
            auth_tag = base64.b64decode(data['tag'])
            
            # Validate component lengths
            if len(nonce) != self.nonce_length:
                raise IntegrityError(f"Invalid nonce length: {len(nonce)}")
            
            if len(auth_tag) != 16:
                raise IntegrityError(f"Invalid authentication tag length: {len(auth_tag)}")
            
            # Reconstruct full ciphertext (ciphertext + tag for AESGCM)
            full_ciphertext = ciphertext_only + auth_tag
            
            # Initialize AES-GCM cipher
            aesgcm = AESGCM(key)
            
            # Decrypt and verify authentication
            plaintext_bytes = aesgcm.decrypt(nonce, full_ciphertext, None)
            
            # Decode to string
            plaintext = plaintext_bytes.decode('utf-8')
            
            return plaintext
            
        except base64.binascii.Error as e:
            raise ValueError(f"Invalid base64 encoding: {e}")
        except UnicodeDecodeError as e:
            raise IntegrityError(f"Decrypted data is not valid UTF-8: {e}")
        except Exception as e:
            if isinstance(e, (ValueError, IntegrityError)):
                raise
            # Authentication failure or other decryption error
            raise DecryptionError(f"Decryption failed: {e}")
    
    def encrypt_field(self, data: str, session_key: bytes) -> str:
        """Encrypt sensitive database field using session-specific key.
        
        Args:
            data: Field data to encrypt
            session_key: Session-derived encryption key
            
        Returns:
            Encrypted field as JSON string
        """
        return self.encrypt_password(data, session_key)
    
    def decrypt_field(self, encrypted_field: str, session_key: bytes) -> str:
        """Decrypt sensitive database field.
        
        Args:
            encrypted_field: Encrypted field JSON string
            session_key: Session-derived encryption key
            
        Returns:
            Decrypted field data
        """
        return self.decrypt_password(encrypted_field, session_key)
    
    def generate_key(self) -> bytes:
        """Generate a secure 256-bit AES key.
        
        Returns:
            32 bytes of cryptographically secure random data
        """
        return secrets.token_bytes(self.key_length)
    
    def verify_encrypted_format(self, encrypted_data: str) -> bool:
        """Verify that encrypted data has correct format without decrypting.
        
        Args:
            encrypted_data: JSON string to verify
            
        Returns:
            True if format is valid, False otherwise
        """
        try:
            data = json.loads(encrypted_data)
            required_fields = {'nonce', 'ciphertext', 'tag', 'algorithm'}
            
            if not all(field in data for field in required_fields):
                return False
            
            if data['algorithm'] != self.algorithm_name:
                return False
            
            # Verify base64 encoding and lengths
            nonce = base64.b64decode(data['nonce'])
            ciphertext = base64.b64decode(data['ciphertext'])
            tag = base64.b64decode(data['tag'])
            
            return (len(nonce) == self.nonce_length and 
                   len(tag) == 16 and 
                   len(ciphertext) > 0)
            
        except:
            return False
    
    def get_encryption_info(self) -> dict:
        """Get information about current encryption configuration.
        
        Returns:
            Dictionary containing encryption details
        """
        return {
            'algorithm': self.algorithm_name,
            'key_length_bits': self.key_length * 8,
            'key_length_bytes': self.key_length,
            'nonce_length_bits': self.nonce_length * 8,
            'nonce_length_bytes': self.nonce_length,
            'tag_length_bytes': 16,
            'authenticated_encryption': True,
            'provides_confidentiality': True,
            'provides_authenticity': True,
            'provides_integrity': True
        }


# Custom exception classes for encryption operations
class EncryptionError(Exception):
    """Raised when encryption operations fail."""
    pass


class DecryptionError(Exception):
    """Raised when decryption operations fail."""
    pass


class IntegrityError(Exception):
    """Raised when data integrity checks fail."""
    pass