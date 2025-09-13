"""CLI decorators for session management.

Provides decorators to handle session authentication for CLI commands.
"""
import functools
import getpass
import sys
import json
from typing import Callable, Any
from rich.console import Console

from src.services.auth_service import AuthenticationService

console = Console()


def require_session(func: Callable) -> Callable:
    """Decorator to require valid session for CLI commands.
    
    This decorator checks for an existing valid session and prompts for
    authentication if no valid session exists.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Extract format and quiet options if they exist
        format_output = kwargs.get('format', 'table')
        quiet = kwargs.get('quiet', False)
        
        auth_service = AuthenticationService()
        
        # Check for existing session
        current_session = auth_service.session_service.get_current_session()
        
        if current_session and current_session.is_active():
            # Valid session exists, extend it
            extended_session = auth_service.session_service.extend_session(current_session.id)
            if extended_session:
                # Session extended successfully, proceed with command
                kwargs['session'] = extended_session
                return func(*args, **kwargs)
        
        # No valid session, need to authenticate
        if not quiet and format_output != "json":
            console.print("Session expired or not found. Please authenticate.")
        
        try:
            password = getpass.getpass("Master password: ")
        except KeyboardInterrupt:
            if format_output == "json":
                error_output = {
                    "status": "error", 
                    "error_code": "AUTHENTICATION_CANCELLED",
                    "message": "Authentication cancelled"
                }
                print(json.dumps(error_output))
            else:
                console.print("\nAuthentication cancelled.")
            sys.exit(1)
        
        # Authenticate and create new session
        success, session, error_msg = auth_service.authenticate(password, timeout_minutes=15)
        
        if not success or not session:
            if format_output == "json":
                error_output = {
                    "status": "error",
                    "error_code": "AUTHENTICATION_FAILED", 
                    "message": error_msg or "Authentication failed"
                }
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg or 'Authentication failed'}")
            sys.exit(2)
        
        # Authentication successful, add session to kwargs
        kwargs['session'] = session
        
        if not quiet and format_output != "json":
            console.print(f"[green]✓[/green] Authentication successful. Session valid for 15 minutes.")
        
        return func(*args, **kwargs)
    
    return wrapper


def optional_session(func: Callable) -> Callable:
    """Decorator that provides session if available but doesn't require it.
    
    This decorator checks for an existing session and provides it to the
    command if available, but doesn't require authentication.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        auth_service = AuthenticationService()
        
        # Check for existing session
        current_session = auth_service.session_service.get_current_session()
        
        if current_session and current_session.is_active():
            # Extend the session
            extended_session = auth_service.session_service.extend_session(current_session.id)
            kwargs['session'] = extended_session
        else:
            kwargs['session'] = None
        
        return func(*args, **kwargs)
    
    return wrapper