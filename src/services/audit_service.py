"""Audit Service.

Handles security audit logging for authentication and session events.
"""
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from src.models.auth_event import AuthEvent, EventType
from src.config.session_config import (
    AUDIT_LOG_FILE_NAME,
    AUDIT_LOG_RETENTION_DAYS,
    AUDIT_LOG_MAX_SIZE_MB,
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


class AuditService:
    """Service for security audit logging."""
    
    def __init__(self):
        """Initialize audit service."""
        self.audit_dir = self._get_audit_directory()
        self._ensure_audit_dir()
    
    def _get_audit_directory(self) -> Path:
        """Get platform-specific audit log directory."""
        data_dir = platformdirs.user_data_dir(APP_NAME, APP_AUTHOR)
        return Path(data_dir)
    
    def _ensure_audit_dir(self) -> None:
        """Ensure audit directory exists with proper permissions."""
        if not self.audit_dir.exists():
            self.audit_dir.mkdir(parents=True, mode=0o700)
        else:
            # Ensure proper permissions on existing directory
            self.audit_dir.chmod(0o700)
    
    def _get_audit_file_path(self) -> Path:
        """Get the audit log file path."""
        return self.audit_dir / AUDIT_LOG_FILE_NAME
    
    def log_event(self, event_type: str, username: str, success: bool,
                  session_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Log an audit event.
        
        Args:
            event_type: Type of event (must be valid EventType)
            username: Username associated with event
            success: Whether the operation was successful
            session_id: Session ID if applicable
            details: Additional event details
            
        Returns:
            Dict with event_id and logged_at timestamp
            
        Raises:
            ValueError: If event data is invalid
            IOError: If logging fails
        """
        # Validate event type
        valid_types = [e.value for e in EventType]
        if event_type not in valid_types:
            raise ValueError(f"Invalid event type: {event_type}")
        
        # Validate username
        if not username or not username.strip():
            raise ValueError("Username is required")
        
        # Validate session_id if provided
        if session_id is not None:
            import uuid
            try:
                uuid.UUID(session_id, version=4)
            except ValueError:
                raise ValueError("Invalid session ID format")
        
        # Create audit event
        event = AuthEvent(
            event_type=event_type,
            username=username,
            success=success,
            session_id=session_id,
            details=details or {}
        )
        
        # Write to log file
        self._write_event(event)
        
        return {
            'event_id': event.id,
            'logged_at': event.timestamp.isoformat()
        }
    
    def _write_event(self, event: AuthEvent) -> None:
        """Write event to audit log file."""
        audit_file = self._get_audit_file_path()
        
        try:
            # Append to log file (create if doesn't exist)
            with open(audit_file, 'a', encoding='utf-8') as f:
                f.write(event.to_json_line() + '\n')
            
            # Set proper permissions if file was just created
            if audit_file.stat().st_size == len(event.to_json_line()) + 1:
                audit_file.chmod(0o600)
                
        except Exception as e:
            raise IOError(f"Failed to write audit log: {e}")
    
    def query_events(self, username: Optional[str] = None, event_type: Optional[str] = None,
                     from_date: Optional[datetime] = None, to_date: Optional[datetime] = None,
                     limit: int = 100) -> Dict[str, Any]:
        """Query audit events with filters.
        
        Args:
            username: Filter by username
            event_type: Filter by event type
            from_date: Filter events after this date
            to_date: Filter events before this date
            limit: Maximum number of events to return (1-1000)
            
        Returns:
            Dict with events list, total count, and has_more flag
            
        Raises:
            ValueError: If parameters are invalid
        """
        # Validate event_type if provided
        if event_type is not None:
            valid_types = [e.value for e in EventType]
            if event_type not in valid_types:
                raise ValueError(f"Invalid event type: {event_type}")
        
        # Validate limit
        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000")
        
        audit_file = self._get_audit_file_path()
        
        if not audit_file.exists():
            return {
                'events': [],
                'total': 0,
                'has_more': False
            }
        
        try:
            events = []
            total_count = 0
            
            with open(audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = AuthEvent.from_json_line(line)
                        
                        # Apply filters
                        if username and event.username != username:
                            continue
                        
                        if event_type and event.event_type != event_type:
                            continue
                        
                        if from_date and event.timestamp < from_date:
                            continue
                        
                        if to_date and event.timestamp > to_date:
                            continue
                        
                        # Count all matching events
                        total_count += 1
                        
                        # Only collect up to limit
                        if len(events) < limit:
                            events.append({
                                'id': event.id,
                                'event_type': event.event_type,
                                'timestamp': event.timestamp.isoformat(),
                                'username': event.username,
                                'session_id': event.session_id,
                                'success': event.success,
                                'details': event.details
                            })
                    
                    except (ValueError, json.JSONDecodeError):
                        # Skip malformed lines
                        continue
            
            return {
                'events': events,
                'total': total_count,
                'has_more': total_count > limit
            }
            
        except Exception as e:
            raise IOError(f"Failed to query audit log: {e}")
    
    def cleanup_old_logs(self) -> int:
        """Clean up audit logs older than retention period.
        
        Returns:
            Number of events removed
        """
        audit_file = self._get_audit_file_path()
        
        if not audit_file.exists():
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=AUDIT_LOG_RETENTION_DAYS)
        kept_events = []
        removed_count = 0
        
        try:
            with open(audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = AuthEvent.from_json_line(line)
                        
                        if event.timestamp >= cutoff_date:
                            kept_events.append(line)
                        else:
                            removed_count += 1
                            
                    except (ValueError, json.JSONDecodeError):
                        # Keep malformed lines (don't remove data)
                        kept_events.append(line)
            
            # Rewrite file with kept events
            if removed_count > 0:
                with open(audit_file, 'w', encoding='utf-8') as f:
                    for line in kept_events:
                        f.write(line + '\n')
            
            return removed_count
            
        except Exception:
            return 0
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        audit_file = self._get_audit_file_path()
        
        if not audit_file.exists():
            return {
                'total_events': 0,
                'file_size': 0,
                'oldest_event': None,
                'newest_event': None
            }
        
        try:
            stat_info = audit_file.stat()
            total_events = 0
            oldest_event = None
            newest_event = None
            
            with open(audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = AuthEvent.from_json_line(line)
                        total_events += 1
                        
                        if oldest_event is None or event.timestamp < oldest_event:
                            oldest_event = event.timestamp
                        
                        if newest_event is None or event.timestamp > newest_event:
                            newest_event = event.timestamp
                            
                    except (ValueError, json.JSONDecodeError):
                        continue
            
            return {
                'total_events': total_events,
                'file_size': stat_info.st_size,
                'oldest_event': oldest_event.isoformat() if oldest_event else None,
                'newest_event': newest_event.isoformat() if newest_event else None
            }
            
        except Exception:
            return {
                'total_events': 0,
                'file_size': 0,
                'oldest_event': None,
                'newest_event': None
            }