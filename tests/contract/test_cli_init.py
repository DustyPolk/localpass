"""Contract tests for the init command.

These tests verify the CLI interface contract for initialization.
They MUST fail before implementation exists (TDD requirement).
"""
import json
import subprocess
import pytest
from pathlib import Path


class TestInitCommandContract:
    """Test init command follows the CLI interface contract."""

    def test_init_command_basic_usage(self):
        """Test basic init command creates database and outputs success."""
        # This test MUST fail until implementation exists
        result = subprocess.run(
            ['uv', 'run', 'localpass', 'init'], 
            capture_output=True, 
            text=True,
            input='testpassword123\ntestpassword123\n'  # Master password + confirmation
        )
        
        assert result.returncode == 0
        assert "✓ Password manager initialized successfully" in result.stdout
        assert "Username:" in result.stdout
        assert "Database:" in result.stdout

    def test_init_command_json_format(self):
        """Test init command with JSON output format."""
        result = subprocess.run(
            ['localpass', 'init', '--format', 'json'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output['status'] == 'success'
        assert output['action'] == 'init'
        assert 'username' in output
        assert 'database_path' in output

    def test_init_command_with_username(self):
        """Test init command with custom username."""
        result = subprocess.run(
            ['localpass', 'init', '--username', 'testuser'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        assert result.returncode == 0
        assert "Username: testuser" in result.stdout

    def test_init_command_force_overwrite(self):
        """Test init command with --force flag overwrites existing database."""
        # First init
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        # Second init with force
        result = subprocess.run(
            ['localpass', 'init', '--force'],
            capture_output=True,
            text=True,
            input='newpassword456\nnewpassword456\n'
        )
        
        assert result.returncode == 0
        assert "✓ Password manager initialized successfully" in result.stdout

    def test_init_command_without_force_fails_if_exists(self):
        """Test init command fails when database exists without --force."""
        # First init
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        # Second init without force should fail
        result = subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='newpassword456\nnewpassword456\n'
        )
        
        assert result.returncode != 0
        assert "already exists" in result.stderr or "already initialized" in result.stderr

    def test_init_command_password_mismatch(self):
        """Test init command fails when password confirmation doesn't match."""
        result = subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='testpassword123\ndifferentpassword\n'
        )
        
        assert result.returncode != 0
        assert "do not match" in result.stderr or "mismatch" in result.stderr

    def test_init_command_weak_password(self):
        """Test init command rejects weak passwords."""
        result = subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='123\n123\n'  # Too short
        )
        
        assert result.returncode != 0
        assert "weak" in result.stderr or "length" in result.stderr

    def test_init_command_help(self):
        """Test init command shows help information."""
        result = subprocess.run(
            ['localpass', 'init', '--help'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Initialize the password manager" in result.stdout
        assert "--username" in result.stdout
        assert "--force" in result.stdout

    def test_init_command_creates_database_file(self):
        """Test init command creates database file in expected location."""
        result = subprocess.run(
            ['localpass', 'init', '--format', 'json'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        assert result.returncode == 0
        output = json.loads(result.stdout)
        db_path = Path(output['database_path']).expanduser()
        assert db_path.exists()

    def test_init_command_quiet_mode(self):
        """Test init command with --quiet flag suppresses non-essential output."""
        result = subprocess.run(
            ['localpass', 'init', '--quiet'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n'
        )
        
        assert result.returncode == 0
        # Quiet mode should have minimal output
        assert len(result.stdout.strip().split('\n')) <= 2