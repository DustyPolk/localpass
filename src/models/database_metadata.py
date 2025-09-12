"""Database Metadata data model.

Represents database configuration and integrity information.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import hashlib


@dataclass
class DatabaseMetadata:
    """Database configuration and integrity tracking."""
    
    # Required fields
    version: str
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation_algorithm: str = "PBKDF2-SHA256"
    
    # Auto-generated fields
    id: int = 1  # Always 1 - single record
    created_at: datetime = field(default_factory=datetime.now)
    
    # Optional tracking fields
    last_backup_at: Optional[datetime] = None
    total_entries: int = 0
    integrity_hash: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate database metadata after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate database metadata fields according to contract."""
        # ID validation - must always be 1
        if self.id != 1:
            raise ValueError("Database metadata ID must be 1")
        
        # Version validation (semantic versioning)
        if not self.version or not self._is_valid_semver(self.version):
            raise ValueError("Version must follow semantic versioning (MAJOR.MINOR.PATCH)")
        
        # Algorithm validation
        supported_encryption = {"AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"}
        if self.encryption_algorithm not in supported_encryption:
            raise ValueError(f"Encryption algorithm must be one of: {supported_encryption}")
        
        supported_kdf = {"PBKDF2-SHA256", "PBKDF2-SHA512", "Argon2id"}
        if self.key_derivation_algorithm not in supported_kdf:
            raise ValueError(f"Key derivation algorithm must be one of: {supported_kdf}")
        
        # Entry count validation
        if self.total_entries < 0:
            raise ValueError("Total entries cannot be negative")
    
    def _is_valid_semver(self, version: str) -> bool:
        """Check if version follows semantic versioning format.
        
        Args:
            version: Version string to validate
            
        Returns:
            True if valid semver format, False otherwise
        """
        try:
            parts = version.split('.')
            if len(parts) != 3:
                return False
            
            # Check each part is a non-negative integer
            for part in parts:
                if not part.isdigit():
                    return False
                if int(part) < 0:
                    return False
            
            return True
        except:
            return False
    
    def update_entry_count(self, count: int) -> None:
        """Update the total entry count.
        
        Args:
            count: New total number of password entries
        """
        if count < 0:
            raise ValueError("Entry count cannot be negative")
        self.total_entries = count
    
    def calculate_integrity_hash(self, entry_ids: list[int]) -> str:
        """Calculate integrity hash from sorted entry IDs.
        
        Args:
            entry_ids: List of password entry IDs
            
        Returns:
            SHA-256 hash of sorted entry IDs
        """
        # Sort IDs to ensure consistent hash regardless of order
        sorted_ids = sorted(entry_ids)
        
        # Create hash input from sorted IDs
        hash_input = ','.join(str(id) for id in sorted_ids)
        
        # Calculate SHA-256 hash
        hash_bytes = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        
        # Update internal hash
        self.integrity_hash = hash_bytes
        
        return hash_bytes
    
    def verify_integrity(self, entry_ids: list[int]) -> bool:
        """Verify database integrity against stored hash.
        
        Args:
            entry_ids: Current list of password entry IDs
            
        Returns:
            True if integrity check passes, False otherwise
        """
        if self.integrity_hash is None:
            return True  # No hash to verify against
        
        current_hash = self.calculate_integrity_hash(entry_ids)
        return current_hash == self.integrity_hash
    
    def mark_backup(self, backup_time: Optional[datetime] = None) -> None:
        """Mark when a backup was created.
        
        Args:
            backup_time: When backup was created (defaults to now)
        """
        self.last_backup_at = backup_time or datetime.now()
    
    def get_schema_info(self) -> dict:
        """Get database schema information.
        
        Returns:
            Dictionary containing schema details
        """
        return {
            'version': self.version,
            'encryption_algorithm': self.encryption_algorithm,
            'key_derivation_algorithm': self.key_derivation_algorithm,
            'created_at': self.created_at.isoformat(),
            'supports_migration': True,
            'schema_hash': hashlib.sha256(
                f"{self.version}{self.encryption_algorithm}{self.key_derivation_algorithm}".encode()
            ).hexdigest()[:16]
        }
    
    def to_dict(self) -> dict:
        """Convert database metadata to dictionary representation."""
        return {
            'id': self.id,
            'version': self.version,
            'encryption_algorithm': self.encryption_algorithm,
            'key_derivation_algorithm': self.key_derivation_algorithm,
            'created_at': self.created_at.isoformat(),
            'last_backup_at': self.last_backup_at.isoformat() if self.last_backup_at else None,
            'total_entries': self.total_entries,
            'integrity_hash': self.integrity_hash,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DatabaseMetadata':
        """Create database metadata from dictionary representation.
        
        Args:
            data: Dictionary containing database metadata
            
        Returns:
            DatabaseMetadata instance
        """
        # Parse datetime fields
        created_at = datetime.fromisoformat(data['created_at'])
        last_backup_at = datetime.fromisoformat(data['last_backup_at']) if data['last_backup_at'] else None
        
        return cls(
            id=data['id'],
            version=data['version'],
            encryption_algorithm=data['encryption_algorithm'],
            key_derivation_algorithm=data['key_derivation_algorithm'],
            created_at=created_at,
            last_backup_at=last_backup_at,
            total_entries=data['total_entries'],
            integrity_hash=data.get('integrity_hash'),
        )
    
    @classmethod
    def from_database_row(cls, row: tuple) -> 'DatabaseMetadata':
        """Create database metadata from database row tuple.
        
        Args:
            row: Database row tuple (id, version, encryption_algorithm,
                 key_derivation_algorithm, created_at, last_backup_at)
                 
        Returns:
            DatabaseMetadata instance
        """
        last_backup_at = datetime.fromisoformat(row[5]) if row[5] else None
        
        return cls(
            id=row[0],
            version=row[1],
            encryption_algorithm=row[2],
            key_derivation_algorithm=row[3],
            created_at=datetime.fromisoformat(row[4]),
            last_backup_at=last_backup_at,
        )
    
    @classmethod
    def create_initial(cls, version: str = "1.0.0") -> 'DatabaseMetadata':
        """Create initial database metadata for new database.
        
        Args:
            version: Initial database version
            
        Returns:
            New DatabaseMetadata instance
        """
        return cls(version=version)
    
    def __str__(self) -> str:
        """String representation for debugging."""
        return f"DatabaseMetadata(v{self.version}, {self.total_entries} entries)"