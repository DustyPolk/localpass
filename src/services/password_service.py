"""Password Service.

Handles CRUD operations for password entries with encryption.
"""
import sqlite3
from datetime import datetime
from typing import List, Optional, Tuple
from src.models.password_entry import PasswordEntry
from src.models.session import Session
from src.services.database_service import DatabaseService
from src.services.encryption_service import EncryptionService, EncryptionError, DecryptionError


class PasswordService:
    """Service for password entry CRUD operations."""
    
    def __init__(self, database_service: Optional[DatabaseService] = None):
        """Initialize password service.
        
        Args:
            database_service: Database service instance (creates new if None)
        """
        self.db_service = database_service or DatabaseService()
        self.encryption_service = EncryptionService()
    
    def add_password(self, session: Session, service: str, username: str, 
                    password: str, url: Optional[str] = None, 
                    notes: Optional[str] = None) -> Tuple[bool, Optional[int], Optional[str]]:
        """Add a new password entry.
        
        Args:
            session: Active user session
            service: Service name
            username: Username for the service
            password: Password to store
            url: Optional service URL
            notes: Optional notes
            
        Returns:
            Tuple of (success: bool, entry_id: Optional[int], error_message: Optional[str])
        """
        try:
            # Validate session is active
            if not session.is_active():
                return False, None, "Session expired"
            
            # Check for duplicate service/username combination
            if self._entry_exists(service, username):
                return False, None, f"Entry for {service} with username {username} already exists"
            
            # Encrypt password and notes
            encrypted_password = self.encryption_service.encrypt_password(password, session.derived_key)
            encrypted_notes = None
            if notes:
                encrypted_notes = self.encryption_service.encrypt_password(notes, session.derived_key)
            
            # Create password entry
            entry = PasswordEntry(
                service=service,
                username=username,
                encrypted_password=encrypted_password,
                url=url,
                encrypted_notes=encrypted_notes
            )
            
            # Insert into database
            conn = self.db_service.connect()
            cursor = conn.execute('''
                INSERT INTO password_entries 
                (service, username, encrypted_password, url, encrypted_notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.service,
                entry.username,
                entry.encrypted_password,
                entry.url,
                entry.encrypted_notes,
                entry.created_at.isoformat(),
                entry.updated_at.isoformat()
            ))
            conn.commit()
            
            entry_id = cursor.lastrowid
            
            # Update session activity
            session.update_activity()
            
            return True, entry_id, None
            
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                return False, None, f"Entry for {service} with username {username} already exists"
            return False, None, f"Database error: {e}"
        except EncryptionError as e:
            return False, None, f"Encryption failed: {e}"
        except Exception as e:
            return False, None, f"Failed to add password: {e}"
    
    def get_password(self, session: Session, service: str, 
                    username: Optional[str] = None) -> Tuple[bool, Optional[List[dict]], Optional[str]]:
        """Get password entries for a service.
        
        Args:
            session: Active user session
            service: Service name to search for
            username: Optional specific username to filter by
            
        Returns:
            Tuple of (success: bool, entries: Optional[List[dict]], error_message: Optional[str])
        """
        try:
            # Validate session is active
            if not session.is_active():
                return False, None, "Session expired"
            
            # Build query
            if username:
                query = 'SELECT * FROM password_entries WHERE service = ? AND username = ?'
                params = (service, username)
            else:
                query = 'SELECT * FROM password_entries WHERE service = ?'
                params = (service,)
            
            # Execute query
            conn = self.db_service.connect()
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            
            if not rows:
                return False, None, f"No entries found for service: {service}"
            
            # Decrypt and format entries
            entries = []
            for row in rows:
                entry = PasswordEntry.from_database_row(row)
                
                # Decrypt password
                try:
                    decrypted_password = self.encryption_service.decrypt_password(
                        entry.encrypted_password, session.derived_key
                    )
                except DecryptionError:
                    return False, None, "Failed to decrypt password - session key may be invalid"
                
                # Decrypt notes if present
                decrypted_notes = None
                if entry.encrypted_notes:
                    try:
                        decrypted_notes = self.encryption_service.decrypt_password(
                            entry.encrypted_notes, session.derived_key
                        )
                    except DecryptionError:
                        # Notes decryption failure is not critical
                        decrypted_notes = "[Decryption failed]"
                
                # Calculate password strength
                strength = entry.get_password_strength(decrypted_password)
                
                entries.append({
                    'id': entry.id,
                    'service': entry.service,
                    'username': entry.username,
                    'password': decrypted_password,
                    'url': entry.url,
                    'notes': decrypted_notes,
                    'created_at': entry.created_at.isoformat(),
                    'updated_at': entry.updated_at.isoformat(),
                    'password_strength': strength
                })
            
            # Update session activity
            session.update_activity()
            
            return True, entries, None
            
        except Exception as e:
            return False, None, f"Failed to retrieve password: {e}"
    
    def list_passwords(self, session: Session, service_pattern: Optional[str] = None,
                      limit: int = 100) -> Tuple[bool, Optional[List[dict]], Optional[str]]:
        """List password entries with optional filtering.
        
        Args:
            session: Active user session
            service_pattern: Optional service name pattern (supports *)
            limit: Maximum number of entries to return
            
        Returns:
            Tuple of (success: bool, entries: Optional[List[dict]], error_message: Optional[str])
        """
        try:
            # Validate session is active
            if not session.is_active():
                return False, None, "Session expired"
            
            # Build query
            if service_pattern:
                # Convert shell-style wildcards to SQL wildcards
                sql_pattern = service_pattern.replace('*', '%')
                query = '''
                    SELECT * FROM password_entries 
                    WHERE service LIKE ? 
                    ORDER BY updated_at DESC 
                    LIMIT ?
                '''
                params = (sql_pattern, limit)
            else:
                query = '''
                    SELECT * FROM password_entries 
                    ORDER BY updated_at DESC 
                    LIMIT ?
                '''
                params = (limit,)
            
            # Execute query
            conn = self.db_service.connect()
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            
            # Format entries (without decrypting passwords for list view)
            entries = []
            for row in rows:
                entry = PasswordEntry.from_database_row(row)
                
                entries.append({
                    'id': entry.id,
                    'service': entry.service,
                    'username': entry.username,
                    'url': entry.url,
                    'created_at': entry.created_at.isoformat(),
                    'updated_at': entry.updated_at.isoformat(),
                    'has_notes': entry.encrypted_notes is not None
                })
            
            # Update session activity
            session.update_activity()
            
            return True, entries, None
            
        except Exception as e:
            return False, None, f"Failed to list passwords: {e}"
    
    def update_password(self, session: Session, service: str, username: str,
                       new_password: Optional[str] = None, new_url: Optional[str] = None,
                       new_notes: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Update an existing password entry.
        
        Args:
            session: Active user session
            service: Service name
            username: Username for the service
            new_password: New password (None to keep current)
            new_url: New URL (None to keep current)
            new_notes: New notes (None to keep current)
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            # Validate session is active
            if not session.is_active():
                return False, "Session expired"
            
            # Check if entry exists
            if not self._entry_exists(service, username):
                return False, f"No entry found for {service} with username {username}"
            
            # Build update query parts
            updates = []
            params = []
            
            if new_password:
                encrypted_password = self.encryption_service.encrypt_password(new_password, session.derived_key)
                updates.append("encrypted_password = ?")
                params.append(encrypted_password)
            
            if new_url is not None:  # Allow empty string to clear URL
                updates.append("url = ?")
                params.append(new_url if new_url else None)
            
            if new_notes is not None:  # Allow empty string to clear notes
                if new_notes:
                    encrypted_notes = self.encryption_service.encrypt_password(new_notes, session.derived_key)
                    updates.append("encrypted_notes = ?")
                    params.append(encrypted_notes)
                else:
                    updates.append("encrypted_notes = NULL")
            
            if not updates:
                return False, "No updates specified"
            
            # Add updated timestamp
            updates.append("updated_at = ?")
            params.append(datetime.now().isoformat())
            
            # Add WHERE clause parameters
            params.extend([service, username])
            
            # Execute update
            query = f'''
                UPDATE password_entries 
                SET {", ".join(updates)}
                WHERE service = ? AND username = ?
            '''
            
            conn = self.db_service.connect()
            cursor = conn.execute(query, params)
            conn.commit()
            
            if cursor.rowcount == 0:
                return False, f"Entry for {service} with username {username} not found"
            
            # Update session activity
            session.update_activity()
            
            return True, None
            
        except EncryptionError as e:
            return False, f"Encryption failed: {e}"
        except Exception as e:
            return False, f"Failed to update password: {e}"
    
    def delete_password(self, session: Session, service: str, 
                       username: str) -> Tuple[bool, Optional[str]]:
        """Delete a password entry.
        
        Args:
            session: Active user session
            service: Service name
            username: Username for the service
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            # Validate session is active
            if not session.is_active():
                return False, "Session expired"
            
            # Delete entry
            conn = self.db_service.connect()
            cursor = conn.execute('''
                DELETE FROM password_entries 
                WHERE service = ? AND username = ?
            ''', (service, username))
            conn.commit()
            
            if cursor.rowcount == 0:
                return False, f"No entry found for {service} with username {username}"
            
            # Update session activity
            session.update_activity()
            
            return True, None
            
        except Exception as e:
            return False, f"Failed to delete password: {e}"
    
    def search_passwords(self, session: Session, search_term: str,
                        limit: int = 50) -> Tuple[bool, Optional[List[dict]], Optional[str]]:
        """Search password entries by service name or username.
        
        Args:
            session: Active user session
            search_term: Term to search for (in service name or username)
            limit: Maximum number of results
            
        Returns:
            Tuple of (success: bool, entries: Optional[List[dict]], error_message: Optional[str])
        """
        try:
            # Validate session is active
            if not session.is_active():
                return False, None, "Session expired"
            
            # Search in service names and usernames
            search_pattern = f"%{search_term}%"
            query = '''
                SELECT * FROM password_entries 
                WHERE service LIKE ? OR username LIKE ?
                ORDER BY updated_at DESC 
                LIMIT ?
            '''
            
            conn = self.db_service.connect()
            cursor = conn.execute(query, (search_pattern, search_pattern, limit))
            rows = cursor.fetchall()
            
            # Format entries (without passwords for search results)
            entries = []
            for row in rows:
                entry = PasswordEntry.from_database_row(row)
                
                entries.append({
                    'id': entry.id,
                    'service': entry.service,
                    'username': entry.username,
                    'url': entry.url,
                    'created_at': entry.created_at.isoformat(),
                    'updated_at': entry.updated_at.isoformat(),
                    'has_notes': entry.encrypted_notes is not None
                })
            
            # Update session activity
            session.update_activity()
            
            return True, entries, None
            
        except Exception as e:
            return False, None, f"Search failed: {e}"
    
    def get_password_count(self) -> int:
        """Get total number of password entries.
        
        Returns:
            Total number of entries in database
        """
        try:
            conn = self.db_service.connect()
            cursor = conn.execute('SELECT COUNT(*) FROM password_entries')
            return cursor.fetchone()[0]
        except:
            return 0
    
    def _entry_exists(self, service: str, username: str) -> bool:
        """Check if password entry exists.
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            True if entry exists
        """
        try:
            conn = self.db_service.connect()
            cursor = conn.execute('''
                SELECT 1 FROM password_entries 
                WHERE service = ? AND username = ? 
                LIMIT 1
            ''', (service, username))
            return cursor.fetchone() is not None
        except:
            return False