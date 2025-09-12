"""Contract tests for the auth command.

These tests verify the CLI interface contract for authentication.
They MUST fail before implementation exists (TDD requirement).
"""
import json
import subprocess
import pytest


class TestAuthCommandContract:
    """Test auth command follows the CLI interface contract."""

    def test_auth_command_basic_usage(self):
        """Test basic auth command authenticates successfully."""
        # Initialize first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        # This test MUST fail until implementation exists
        result = subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='testpassword123\n'
        )
        
        assert result.returncode == 0
        assert "✓ Authenticated successfully" in result.stdout
        assert "Session expires in" in result.stdout

    def test_auth_command_json_format(self):
        """Test auth command with JSON output format."""
        # Initialize first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        result = subprocess.run(
            ['localpass', 'auth', '--format', 'json'],
            capture_output=True,
            text=True,
            input='testpassword123\n'
        )
        
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output['status'] == 'success'
        assert output['action'] == 'auth'
        assert 'session_expires_in' in output

    def test_auth_command_wrong_password(self):
        """Test auth command fails with incorrect password."""
        # Initialize first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        result = subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='wrongpassword\n'
        )
        
        assert result.returncode == 2  # Authentication error exit code
        assert "Authentication failed" in result.stderr or "Invalid" in result.stderr

    def test_auth_command_custom_timeout(self):
        """Test auth command with custom session timeout."""
        # Initialize first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        result = subprocess.run(
            ['localpass', 'auth', '--timeout', '30'],
            capture_output=True,
            text=True,
            input='testpassword123\n'
        )
        
        assert result.returncode == 0
        assert "30 minutes" in result.stdout or "expires in 30" in result.stdout

    def test_auth_command_no_database(self):
        """Test auth command fails when no database exists."""
        result = subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='testpassword123\n'
        )
        
        assert result.returncode != 0
        assert "not initialized" in result.stderr or "No database" in result.stderr

    def test_auth_command_locked_account(self):
        """Test auth command handles locked accounts after failed attempts."""
        # Initialize first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        # Make multiple failed attempts
        for _ in range(6):  # Should lock after 5 attempts
            subprocess.run(
                ['localpass', 'auth'],
                capture_output=True,
                text=True,
                input='wrongpassword\n'
            )
        
        # Next attempt should indicate account is locked
        result = subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='testpassword123\n'  # Even correct password should be locked
        )
        
        assert result.returncode == 2
        assert "locked" in result.stderr or "too many attempts" in result.stderr

    def test_auth_command_help(self):
        """Test auth command shows help information."""
        result = subprocess.run(
            ['localpass', 'auth', '--help'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Authenticate with master password" in result.stdout
        assert "--timeout" in result.stdout

    def test_auth_command_status_check(self):
        """Test auth command can check current session status."""
        # Initialize and authenticate first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='testpassword123\n'
        )
        
        result = subprocess.run(
            ['localpass', 'auth', '--status'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Session active" in result.stdout or "Authenticated" in result.stdout

    def test_auth_command_quiet_mode(self):
        """Test auth command with --quiet flag suppresses non-essential output."""
        # Initialize first
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        result = subprocess.run(
            ['localpass', 'auth', '--quiet'],
            capture_output=True,
            text=True,
            input='testpassword123\n'
        )
        
        assert result.returncode == 0
        # Quiet mode should have minimal output
        assert len(result.stdout.strip()) < 50  # Very minimal output