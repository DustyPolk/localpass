"""Main CLI application entry point.

Provides the primary command-line interface for LocalPass.
"""
import typer
import getpass
import sys
import json
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from pathlib import Path

from src.services.database_service import DatabaseService
from src.services.master_password_service import MasterPasswordService
from src.services.auth_service import AuthenticationService
from src.services.password_service import PasswordService
from src.models.master_credential import MasterCredential
from src.cli.decorators import require_session, optional_session

# Initialize Typer app
app = typer.Typer(
    name="localpass",
    help="A secure, minimalist CLI password manager",
    no_args_is_help=True
)

# Rich console for pretty output
console = Console()

# Global format option
FormatOption = typer.Option("table", "--format", "-f", help="Output format: table or json")
QuietOption = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output")


@app.command()
def init(
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Master username"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing database"),
    format: str = FormatOption,
    quiet: bool = QuietOption
) -> None:
    """Initialize the password manager with a master password."""
    try:
        # Get username (default to system user)
        if not username:
            import os
            username = os.getenv('USER') or os.getenv('USERNAME') or 'user'
        
        # Initialize services
        db_service = DatabaseService()
        master_service = MasterPasswordService()
        
        # Check if database already exists
        if db_service.database_exists() and not force:
            error_msg = "Password manager already exists. Use --force to reinitialize."
            if format == "json":
                error_output = {"status": "error", "error_code": "ALREADY_EXISTS", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Get master password
        if not quiet:
            console.print("Creating secure password database...")
        
        while True:
            try:
                password = getpass.getpass("Master password: ")
                if len(password) < 8:
                    console.print("[red]Password must be at least 8 characters long.[/red]", file=sys.stderr)
                    continue
                    
                confirm_password = getpass.getpass("Confirm password: ")
                if password != confirm_password:
                    console.print("[red]Passwords do not match.[/red]", file=sys.stderr)
                    continue
                    
                break
            except KeyboardInterrupt:
                console.print("\nInitialization cancelled.")
                sys.exit(1)
        
        # Initialize database
        db_service.initialize_database(force=force)
        
        # Hash master password
        password_hash = master_service.hash_master_password(password)
        
        # Create master credential record
        import secrets
        salt = secrets.token_bytes(32)
        key_params = {
            "algorithm": "PBKDF2-SHA256",
            "iterations": 600000
        }
        
        master_cred = MasterCredential(
            username=username,
            password_hash=password_hash,
            salt=salt,
            key_derivation_params=key_params
        )
        
        # Store master credential in database
        conn = db_service.connect()
        conn.execute('''
            INSERT INTO master_credential 
            (id, username, password_hash, salt, key_derivation_params, created_at, auth_failure_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            master_cred.id,
            master_cred.username,
            master_cred.password_hash,
            master_cred.salt,
            json.dumps(master_cred.key_derivation_params),
            master_cred.created_at.isoformat(),
            master_cred.auth_failure_count
        ))
        conn.commit()
        
        # Success output
        if format == "json":
            output = {
                "status": "success",
                "action": "init",
                "username": username,
                "database_path": db_service.database_path
            }
            print(json.dumps(output))
        else:
            if not quiet:
                panel = Panel(
                    f"[green]✓[/green] Password manager initialized successfully\n"
                    f"  Username: {username}\n"
                    f"  Database: {db_service.database_path}",
                    border_style="green",
                    padding=(0, 1)
                )
                console.print(panel)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "INIT_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Initialization failed: {e}")
        sys.exit(1)


@app.command()
def auth(
    timeout: int = typer.Option(15, "--timeout", help="Session timeout in minutes"),
    status: bool = typer.Option(False, "--status", help="Check current session status"),
    format: str = FormatOption,
    quiet: bool = QuietOption
) -> None:
    """Authenticate with master password."""
    try:
        # Initialize services
        auth_service = AuthenticationService()
        
        # Handle status check
        if status:
            # For now, just indicate no active sessions (session management is in-memory)
            if format == "json":
                print(json.dumps({"status": "no_active_session", "message": "No active session found"}))
            else:
                console.print("[yellow]No active session found.[/yellow]")
            return
        
        # Check if database exists
        db_service = DatabaseService()
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Get master password
        if not quiet and format != "json":
            console.print("Enter master password to authenticate...")
        
        try:
            password = getpass.getpass("Master password: ")
        except KeyboardInterrupt:
            console.print("\nAuthentication cancelled.")
            sys.exit(1)
        
        # Authenticate
        success, session, error_msg = auth_service.authenticate(password, timeout)
        
        if success and session:
            if format == "json":
                output = {
                    "status": "success",
                    "action": "auth",
                    "session_expires_in": f"{session.get_remaining_minutes()} minutes",
                    "username": session.username
                }
                print(json.dumps(output))
            else:
                if not quiet:
                    panel = Panel(
                        f"[green]✓[/green] Authenticated successfully\n"
                        f"  Session expires in {session.get_remaining_minutes()} minutes",
                        border_style="green",
                        padding=(0, 1)
                    )
                    console.print(panel)
        else:
            if format == "json":
                error_output = {"status": "error", "error_code": "AUTHENTICATION_FAILED", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(2)  # Authentication error exit code
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "AUTH_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Authentication failed: {e}")
        sys.exit(1)


@app.command()
@require_session
def add(
    service: str = typer.Argument(help="Service name"),
    username: str = typer.Option(..., "--username", "-u", help="Username for service"),
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate secure password"),
    length: int = typer.Option(16, "--length", "-l", help="Generated password length"),
    url: Optional[str] = typer.Option(None, "--url", help="Service URL"),
    notes: Optional[str] = typer.Option(None, "--notes", help="Additional notes"),
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None  # Injected by decorator
) -> None:
    """Add a new password entry."""
    try:
        # Initialize services
        db_service = DatabaseService()
        auth_service = AuthenticationService()
        password_service = PasswordService()
        
        # Check if database exists
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Session is already authenticated by decorator
        # session parameter contains the valid session
        
        # Get or generate password
        if generate:
            from src.services.password_generator import PasswordGenerator
            generator = PasswordGenerator()
            password = generator.generate_secure_password(
                length=length,
                include_symbols=True,
                exclude_ambiguous=True
            )
            if not quiet and format != "json":
                console.print(f"Generated secure password ({length} characters)")
        else:
            try:
                password = getpass.getpass("Password for service: ")
                if not password:
                    error_msg = "Password cannot be empty"
                    if format == "json":
                        print(json.dumps({"status": "error", "error_code": "INVALID_INPUT", "message": error_msg}))
                    else:
                        console.print(f"[red]✗[/red] {error_msg}")
                    sys.exit(1)
            except KeyboardInterrupt:
                if format != "json":
                    console.print("\nOperation cancelled.")
                sys.exit(1)
        
        # Add password entry
        success, entry_id, error_msg = password_service.add_password(
            session=session,
            service=service,
            username=username,
            password=password,
            url=url,
            notes=notes
        )
        
        if success:
            if format == "json":
                output = {
                    "status": "success",
                    "action": "add",
                    "entry_id": entry_id,
                    "service": service,
                    "username": username,
                    "url": url,
                    "has_notes": notes is not None
                }
                print(json.dumps(output))
            else:
                if not quiet:
                    panel = Panel(
                        f"[green]✓[/green] Password added successfully\n"
                        f"  Service: {service}\n"
                        f"  Username: {username}" + 
                        (f"\n  URL: {url}" if url else "") +
                        (f"\n  Notes: [dim]Added[/dim]" if notes else ""),
                        border_style="green",
                        padding=(0, 1)
                    )
                    console.print(panel)
        else:
            if format == "json":
                error_output = {"status": "error", "error_code": "ADD_FAILED", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "ADD_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Failed to add password: {e}")
        sys.exit(1)


@app.command()
@require_session
def get(
    service: str = typer.Argument(help="Service name to retrieve"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Specific username (optional)"),
    copy: bool = typer.Option(False, "--copy", "-c", help="Copy password to clipboard"),
    show: bool = typer.Option(False, "--show", "-s", help="Show password in output"),
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None  # Injected by decorator
) -> None:
    """Get password for a service."""
    try:
        # Initialize services
        db_service = DatabaseService()
        auth_service = AuthenticationService()
        password_service = PasswordService()
        
        # Check if database exists
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Session is already authenticated by decorator
        # session parameter contains the valid session
        
        # Retrieve password entries
        success, entries, error_msg = password_service.get_password(session, service, username)
        
        if not success or not entries:
            if format == "json":
                error_output = {"status": "error", "error_code": "NOT_FOUND", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Handle clipboard copy
        if copy:
            if len(entries) == 1:
                try:
                    import pyperclip
                    pyperclip.copy(entries[0]['password'])
                    if not quiet and format != "json":
                        console.print("[green]✓[/green] Password copied to clipboard")
                except ImportError:
                    if format == "json":
                        error_output = {"status": "error", "error_code": "CLIPBOARD_UNAVAILABLE", "message": "Clipboard functionality not available"}
                        print(json.dumps(error_output))
                    else:
                        console.print("[yellow]⚠[/yellow] Clipboard functionality not available")
                except Exception as e:
                    if format == "json":
                        error_output = {"status": "error", "error_code": "CLIPBOARD_FAILED", "message": f"Failed to copy to clipboard: {e}"}
                        print(json.dumps(error_output))
                    else:
                        console.print(f"[yellow]⚠[/yellow] Failed to copy to clipboard: {e}")
            else:
                if format == "json":
                    error_output = {"status": "error", "error_code": "MULTIPLE_ENTRIES", "message": "Cannot copy multiple entries. Specify username."}
                    print(json.dumps(error_output))
                else:
                    console.print("[yellow]⚠[/yellow] Multiple entries found. Cannot copy to clipboard. Specify username.")
        
        # Display results
        if format == "json":
            output = {
                "status": "success",
                "action": "get",
                "service": service,
                "count": len(entries),
                "entries": []
            }
            
            for entry in entries:
                entry_data = {
                    "id": entry['id'],
                    "service": entry['service'],
                    "username": entry['username'],
                    "url": entry['url'],
                    "notes": entry['notes'],
                    "created_at": entry['created_at'],
                    "updated_at": entry['updated_at'],
                    "password_strength": entry['password_strength']
                }
                
                # Only include password if explicitly requested
                if show:
                    entry_data["password"] = entry['password']
                
                output["entries"].append(entry_data)
            
            print(json.dumps(output))
        else:
            if not quiet:
                if len(entries) == 1:
                    entry = entries[0]
                    panel_content = f"[green]✓[/green] Password retrieved for {service}\n"
                    panel_content += f"  Username: {entry['username']}\n"
                    
                    if show:
                        panel_content += f"  Password: [bold]{entry['password']}[/bold]\n"
                    else:
                        panel_content += "  Password: [dim]Hidden (use --show to display)[/dim]\n"
                    
                    if entry['url']:
                        panel_content += f"  URL: {entry['url']}\n"
                    
                    if entry['notes']:
                        panel_content += f"  Notes: {entry['notes']}\n"
                    
                    panel_content += f"  Strength: {entry['password_strength']}"
                    
                    panel = Panel(
                        panel_content,
                        border_style="green",
                        padding=(0, 1)
                    )
                    console.print(panel)
                else:
                    console.print(f"[green]✓[/green] Found {len(entries)} entries for {service}:")
                    from rich.table import Table
                    
                    table = Table()
                    table.add_column("Username", style="cyan")
                    table.add_column("Password", style="yellow" if show else "dim")
                    table.add_column("URL", style="blue")
                    table.add_column("Strength", style="green")
                    table.add_column("Updated", style="magenta")
                    
                    for entry in entries:
                        password_display = entry['password'] if show else "••••••••"
                        url_display = entry['url'] or ""
                        strength_display = entry['password_strength']
                        updated_display = entry['updated_at'][:10]  # Just date part
                        
                        table.add_row(
                            entry['username'],
                            password_display,
                            url_display,
                            strength_display,
                            updated_display
                        )
                    
                    console.print(table)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "GET_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Failed to retrieve password: {e}")
        sys.exit(1)


@app.command()
@require_session
def list_passwords(
    service_pattern: Optional[str] = typer.Option(None, "--service", "-s", help="Service name pattern (supports *)"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum entries to show"),
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None  # Injected by decorator
) -> None:
    """List password entries."""
    try:
        # Initialize services
        db_service = DatabaseService()
        auth_service = AuthenticationService()
        password_service = PasswordService()
        
        # Check if database exists
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Session is already authenticated by decorator
        # session parameter contains the valid session
        
        # List entries
        success, entries, error_msg = password_service.list_passwords(session, service_pattern, limit)
        
        if not success:
            if format == "json":
                error_output = {"status": "error", "error_code": "LIST_FAILED", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Display results
        if format == "json":
            output = {
                "status": "success",
                "action": "list",
                "count": len(entries),
                "entries": entries
            }
            print(json.dumps(output))
        else:
            if not entries:
                console.print("[yellow]No password entries found.[/yellow]")
            else:
                if not quiet:
                    console.print(f"[green]✓[/green] Found {len(entries)} password entries:")
                
                from rich.table import Table
                
                table = Table()
                table.add_column("Service", style="cyan")
                table.add_column("Username", style="yellow")
                table.add_column("URL", style="blue")
                table.add_column("Notes", style="green")
                table.add_column("Updated", style="magenta")
                
                for entry in entries:
                    url_display = entry['url'] or ""
                    notes_display = "Yes" if entry['has_notes'] else ""
                    updated_display = entry['updated_at'][:10]  # Just date part
                    
                    table.add_row(
                        entry['service'],
                        entry['username'],
                        url_display,
                        notes_display,
                        updated_display
                    )
                
                console.print(table)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "LIST_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Failed to list passwords: {e}")
        sys.exit(1)


@app.command()
@require_session
def update(
    service: str = typer.Argument(help="Service name to update"),
    username: str = typer.Argument(help="Username to update"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="New password (prompt if not provided)"),
    url: Optional[str] = typer.Option(None, "--url", help="New URL"),
    notes: Optional[str] = typer.Option(None, "--notes", help="New notes"),
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate new secure password"),
    length: int = typer.Option(16, "--length", "-l", help="Generated password length"),
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None  # Injected by decorator
) -> None:
    """Update an existing password entry."""
    try:
        # Initialize services
        db_service = DatabaseService()
        auth_service = AuthenticationService()
        password_service = PasswordService()
        
        # Check if database exists
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Session is already authenticated by decorator
        # session parameter contains the valid session
        
        # Handle password update
        new_password = password
        if generate:
            from src.services.password_generator import PasswordGenerator
            generator = PasswordGenerator()
            new_password = generator.generate_secure_password(
                length=length,
                include_symbols=True,
                exclude_ambiguous=True
            )
            if not quiet and format != "json":
                console.print(f"Generated new secure password ({length} characters)")
        elif password is None:
            # Prompt for new password
            try:
                new_password = getpass.getpass("New password (leave empty to keep current): ")
                if not new_password:
                    new_password = None
            except KeyboardInterrupt:
                if format != "json":
                    console.print("\nOperation cancelled.")
                sys.exit(1)
        
        # Check if any updates were specified
        if new_password is None and url is None and notes is None:
            error_msg = "No updates specified. Use --password, --url, or --notes."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NO_UPDATES", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Update password entry
        success, error_msg = password_service.update_password(
            session=session,
            service=service,
            username=username,
            new_password=new_password,
            new_url=url,
            new_notes=notes
        )
        
        if success:
            if format == "json":
                output = {
                    "status": "success",
                    "action": "update",
                    "service": service,
                    "username": username,
                    "updated_fields": []
                }
                
                if new_password:
                    output["updated_fields"].append("password")
                if url is not None:
                    output["updated_fields"].append("url")
                if notes is not None:
                    output["updated_fields"].append("notes")
                
                print(json.dumps(output))
            else:
                if not quiet:
                    updated_fields = []
                    if new_password:
                        updated_fields.append("password")
                    if url is not None:
                        updated_fields.append("URL")
                    if notes is not None:
                        updated_fields.append("notes")
                    
                    panel = Panel(
                        f"[green]✓[/green] Password entry updated successfully\n"
                        f"  Service: {service}\n"
                        f"  Username: {username}\n"
                        f"  Updated: {', '.join(updated_fields)}",
                        border_style="green",
                        padding=(0, 1)
                    )
                    console.print(panel)
        else:
            if format == "json":
                error_output = {"status": "error", "error_code": "UPDATE_FAILED", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "UPDATE_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Failed to update password: {e}")
        sys.exit(1)


@app.command()
@require_session
def delete(
    service: str = typer.Argument(help="Service name to delete"),
    username: str = typer.Argument(help="Username to delete"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None  # Injected by decorator
) -> None:
    """Delete a password entry."""
    try:
        # Initialize services
        db_service = DatabaseService()
        auth_service = AuthenticationService()
        password_service = PasswordService()
        
        # Check if database exists
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Session is already authenticated by decorator
        # session parameter contains the valid session
        
        # Confirmation prompt (unless forced or JSON mode)
        if not force and format != "json":
            try:
                confirm = typer.confirm(f"Are you sure you want to delete password for {service} ({username})?")
                if not confirm:
                    console.print("Operation cancelled.")
                    sys.exit(0)
            except KeyboardInterrupt:
                console.print("\nOperation cancelled.")
                sys.exit(1)
        
        # Delete password entry
        success, error_msg = password_service.delete_password(session, service, username)
        
        if success:
            if format == "json":
                output = {
                    "status": "success",
                    "action": "delete",
                    "service": service,
                    "username": username
                }
                print(json.dumps(output))
            else:
                if not quiet:
                    panel = Panel(
                        f"[green]✓[/green] Password entry deleted successfully\n"
                        f"  Service: {service}\n"
                        f"  Username: {username}",
                        border_style="green",
                        padding=(0, 1)
                    )
                    console.print(panel)
        else:
            if format == "json":
                error_output = {"status": "error", "error_code": "DELETE_FAILED", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "DELETE_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Failed to delete password: {e}")
        sys.exit(1)


@app.command()
@require_session
def search(
    term: str = typer.Argument(help="Search term"),
    limit: int = typer.Option(25, "--limit", "-l", help="Maximum results to show"),
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None  # Injected by decorator
) -> None:
    """Search password entries by service name or username."""
    try:
        # Initialize services
        db_service = DatabaseService()
        auth_service = AuthenticationService()
        password_service = PasswordService()
        
        # Check if database exists
        if not db_service.database_exists():
            error_msg = "Password manager not initialized. Run 'localpass init' first."
            if format == "json":
                print(json.dumps({"status": "error", "error_code": "NOT_INITIALIZED", "message": error_msg}))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Session is already authenticated by decorator
        # session parameter contains the valid session
        
        # Search entries
        success, entries, error_msg = password_service.search_passwords(session, term, limit)
        
        if not success:
            if format == "json":
                error_output = {"status": "error", "error_code": "SEARCH_FAILED", "message": error_msg}
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg}")
            sys.exit(1)
        
        # Display results
        if format == "json":
            output = {
                "status": "success",
                "action": "search",
                "term": term,
                "count": len(entries),
                "entries": entries
            }
            print(json.dumps(output))
        else:
            if not entries:
                console.print(f"[yellow]No entries found matching '{term}'.[/yellow]")
            else:
                if not quiet:
                    console.print(f"[green]✓[/green] Found {len(entries)} entries matching '{term}':")
                
                from rich.table import Table
                
                table = Table()
                table.add_column("Service", style="cyan")
                table.add_column("Username", style="yellow")
                table.add_column("URL", style="blue")
                table.add_column("Notes", style="green")
                table.add_column("Updated", style="magenta")
                
                for entry in entries:
                    url_display = entry['url'] or ""
                    notes_display = "Yes" if entry['has_notes'] else ""
                    updated_display = entry['updated_at'][:10]  # Just date part
                    
                    table.add_row(
                        entry['service'],
                        entry['username'],
                        url_display,
                        notes_display,
                        updated_display
                    )
                
                console.print(table)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "SEARCH_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Failed to search passwords: {e}")
        sys.exit(1)


@app.command(name="login")
def login_command(
    timeout: int = typer.Option(15, "--timeout", help="Session timeout in minutes"),
    format: str = FormatOption,
    quiet: bool = QuietOption
) -> None:
    """Login and create a new session."""
    try:
        auth_service = AuthenticationService()
        
        if not quiet and format != "json":
            console.print("Enter master password to create session...")
        
        try:
            password = getpass.getpass("Master password: ")
        except KeyboardInterrupt:
            if format == "json":
                error_output = {
                    "status": "error",
                    "error_code": "AUTHENTICATION_CANCELLED",
                    "message": "Authentication cancelled"
                }
                print(json.dumps(error_output))
            else:
                console.print("\nAuthentication cancelled.")
            sys.exit(1)
        
        # Authenticate and create session
        success, session, error_msg = auth_service.authenticate(password, timeout)
        
        if success and session:
            if format == "json":
                output = {
                    "status": "success",
                    "action": "login",
                    "session_id": session.id,
                    "expires_in_minutes": session.get_remaining_minutes(),
                    "username": session.username
                }
                print(json.dumps(output))
            else:
                console.print(f"[green]✓[/green] Authentication successful.")
                console.print(f"Session created with ID: {session.id[:8]}...")
                console.print(f"Session valid for {session.get_remaining_minutes()} minutes.")
        else:
            if format == "json":
                error_output = {
                    "status": "error",
                    "error_code": "AUTHENTICATION_FAILED",
                    "message": error_msg or "Authentication failed"
                }
                print(json.dumps(error_output))
            else:
                console.print(f"[red]✗[/red] {error_msg or 'Authentication failed'}")
            sys.exit(2)
            
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "LOGIN_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Login failed: {e}")
        sys.exit(1)


@app.command(name="logout")
@optional_session
def logout_command(
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None
) -> None:
    """Logout and terminate current session."""
    try:
        auth_service = AuthenticationService()
        
        if session and session.is_active():
            # Terminate the session
            success = auth_service.logout(session.id)
            
            if success:
                if format == "json":
                    output = {
                        "status": "success",
                        "action": "logout",
                        "message": "Session terminated successfully"
                    }
                    print(json.dumps(output))
                else:
                    if not quiet:
                        console.print("[green]✓[/green] Session terminated successfully.")
            else:
                if format == "json":
                    error_output = {
                        "status": "error",
                        "error_code": "LOGOUT_FAILED",
                        "message": "Failed to terminate session"
                    }
                    print(json.dumps(error_output))
                else:
                    console.print("[red]✗[/red] Failed to terminate session.")
                sys.exit(1)
        else:
            if format == "json":
                output = {
                    "status": "success",
                    "action": "logout",
                    "message": "No active session found"
                }
                print(json.dumps(output))
            else:
                if not quiet:
                    console.print("[yellow]No active session found.[/yellow]")
                    
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "LOGOUT_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Logout failed: {e}")
        sys.exit(1)


@app.command(name="status")
@optional_session
def status_command(
    format: str = FormatOption,
    quiet: bool = QuietOption,
    session=None
) -> None:
    """Check current session status."""
    try:
        if session and session.is_active():
            remaining_minutes = session.get_remaining_minutes()
            
            if format == "json":
                output = {
                    "status": "active",
                    "session_id": session.id,
                    "username": session.username,
                    "created_at": session.created_at.isoformat(),
                    "last_activity_at": session.last_activity_at.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "remaining_minutes": remaining_minutes
                }
                print(json.dumps(output))
            else:
                console.print("[green]Session Active[/green]")
                console.print(f"Session ID: {session.id[:8]}...")
                console.print(f"Username: {session.username}")
                console.print(f"Expires in: {remaining_minutes} minutes")
                console.print(f"Created: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            if format == "json":
                output = {
                    "status": "no_session",
                    "message": "No active session found"
                }
                print(json.dumps(output))
            else:
                console.print("[yellow]No active session found.[/yellow]")
                
    except Exception as e:
        if format == "json":
            error_output = {"status": "error", "error_code": "STATUS_CHECK_FAILED", "message": str(e)}
            print(json.dumps(error_output))
        else:
            console.print(f"[red]✗[/red] Status check failed: {e}")
        sys.exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    from src import __version__
    console.print(f"LocalPass {__version__}")


if __name__ == "__main__":
    app()