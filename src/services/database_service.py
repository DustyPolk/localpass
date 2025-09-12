"""Database Service.

Handles SQLite database initialization, schema creation, and basic operations.
"""
import sqlite3
import os
from pathlib import Path
from typing import Optional, List, Tuple
from src.models.database_metadata import DatabaseMetadata


class DatabaseService:
    """Service for database initialization and schema management."""
    
    def __init__(self, database_path: Optional[str] = None):
        """Initialize database service.
        
        Args:
            database_path: Path to SQLite database file (None for default)
        """
        self.database_path = database_path or self._get_default_database_path()
        self.connection: Optional[sqlite3.Connection] = None
    
    def _get_default_database_path(self) -> str:
        """Get default database path based on platform.
        
        Returns:
            Default database file path
        """
        # Get data directory from environment or use platform default
        data_dir = os.environ.get('LOCALPASS_DATA_DIR')
        
        if not data_dir:
            # Platform-specific default paths
            if os.name == 'nt':  # Windows
                data_dir = Path(os.environ.get('APPDATA', '')) / 'LocalPass'
            elif os.uname().sysname == 'Darwin':  # macOS
                data_dir = Path.home() / 'Library' / 'Application Support' / 'LocalPass'
            else:  # Linux and others
                data_dir = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'localpass'
        else:
            data_dir = Path(data_dir)
        
        # Ensure directory exists with secure permissions
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        return str(data_dir / 'passwords.db')
    
    def database_exists(self) -> bool:
        """Check if database file exists.
        
        Returns:
            True if database file exists
        """
        return Path(self.database_path).exists()
    
    def connect(self) -> sqlite3.Connection:
        """Connect to database and return connection.
        
        Returns:
            SQLite connection object
        """
        if self.connection is None:
            self.connection = sqlite3.connect(
                self.database_path,
                check_same_thread=False,
                timeout=30.0
            )
            # Enable WAL mode for better concurrent access
            self.connection.execute("PRAGMA journal_mode=WAL")
            # Enable foreign key constraints
            self.connection.execute("PRAGMA foreign_keys=ON")
            
        return self.connection
    
    def disconnect(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def initialize_database(self, force: bool = False) -> bool:
        """Initialize database with schema.
        
        Args:
            force: Whether to overwrite existing database
            
        Returns:
            True if database was created, False if already exists
            
        Raises:
            FileExistsError: If database exists and force=False
        """
        if self.database_exists() and not force:
            raise FileExistsError("Database already exists. Use force=True to overwrite.")
        
        # Remove existing database if force=True
        if force and self.database_exists():
            os.remove(self.database_path)
        
        # Create new database
        conn = self.connect()
        
        # Set secure file permissions (owner read/write only)
        os.chmod(self.database_path, 0o600)
        
        # Create tables
        self._create_master_credential_table(conn)
        self._create_password_entries_table(conn)
        self._create_database_metadata_table(conn)
        
        # Insert initial metadata
        metadata = DatabaseMetadata.create_initial()
        self._insert_database_metadata(conn, metadata)
        
        conn.commit()
        return True
    
    def _create_master_credential_table(self, conn: sqlite3.Connection) -> None:
        """Create master_credential table."""
        conn.execute('''
            CREATE TABLE master_credential (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL CHECK (LENGTH(salt) = 32),
                key_derivation_params TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_auth_at TEXT,
                auth_failure_count INTEGER DEFAULT 0,
                locked_until TEXT
            )
        ''')
    
    def _create_password_entries_table(self, conn: sqlite3.Connection) -> None:
        """Create password_entries table."""
        conn.execute('''
            CREATE TABLE password_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                url TEXT,
                encrypted_notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(service, username),
                CHECK (LENGTH(service) BETWEEN 1 AND 100),
                CHECK (LENGTH(username) BETWEEN 1 AND 255)
            )
        ''')
        
        # Create indexes
        conn.execute('CREATE INDEX idx_password_entries_service ON password_entries(service)')
        conn.execute('CREATE INDEX idx_password_entries_updated_at ON password_entries(updated_at)')
        
        # Create update trigger
        conn.execute('''
            CREATE TRIGGER update_password_entries_timestamp 
                AFTER UPDATE ON password_entries
                BEGIN
                    UPDATE password_entries 
                    SET updated_at = CURRENT_TIMESTAMP 
                    WHERE id = NEW.id;
                END
        ''')
    
    def _create_database_metadata_table(self, conn: sqlite3.Connection) -> None:
        """Create database_metadata table."""
        conn.execute('''
            CREATE TABLE database_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version TEXT NOT NULL,
                encryption_algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
                key_derivation_algorithm TEXT NOT NULL DEFAULT 'PBKDF2-SHA256',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_backup_at TEXT
            )
        ''')
    
    def _insert_database_metadata(self, conn: sqlite3.Connection, metadata: DatabaseMetadata) -> None:
        """Insert initial database metadata."""
        conn.execute('''
            INSERT INTO database_metadata 
            (id, version, encryption_algorithm, key_derivation_algorithm, created_at) 
            VALUES (?, ?, ?, ?, ?)
        ''', (
            metadata.id,
            metadata.version,
            metadata.encryption_algorithm,
            metadata.key_derivation_algorithm,
            metadata.created_at.isoformat()
        ))
    
    def get_database_metadata(self) -> Optional[DatabaseMetadata]:
        """Get database metadata.
        
        Returns:
            DatabaseMetadata instance or None if not found
        """
        conn = self.connect()
        cursor = conn.execute('SELECT * FROM database_metadata WHERE id = 1')
        row = cursor.fetchone()
        
        if row:
            return DatabaseMetadata.from_database_row(row)
        return None
    
    def execute_query(self, query: str, params: Optional[Tuple] = None) -> List[Tuple]:
        """Execute a SELECT query and return results.
        
        Args:
            query: SQL SELECT query
            params: Query parameters
            
        Returns:
            List of result tuples
        """
        conn = self.connect()
        cursor = conn.execute(query, params or ())
        return cursor.fetchall()
    
    def execute_update(self, query: str, params: Optional[Tuple] = None) -> int:
        """Execute an INSERT/UPDATE/DELETE query.
        
        Args:
            query: SQL modification query
            params: Query parameters
            
        Returns:
            Number of affected rows
        """
        conn = self.connect()
        cursor = conn.execute(query, params or ())
        conn.commit()
        return cursor.rowcount
    
    def get_last_insert_id(self) -> int:
        """Get ID of last inserted row.
        
        Returns:
            Last insert row ID
        """
        conn = self.connect()
        return conn.lastrowid
    
    def vacuum_database(self) -> None:
        """Optimize database storage."""
        conn = self.connect()
        conn.execute('VACUUM')
    
    def check_integrity(self) -> bool:
        """Check database integrity.
        
        Returns:
            True if database integrity is OK
        """
        try:
            conn = self.connect()
            result = conn.execute('PRAGMA integrity_check').fetchone()
            return result[0] == 'ok'
        except:
            return False
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()