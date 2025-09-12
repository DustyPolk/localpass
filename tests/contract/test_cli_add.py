"""Contract tests for the add command.

These tests verify the CLI interface contract for adding passwords.
They MUST fail before implementation exists (TDD requirement).
"""
import json
import subprocess
import pytest


class TestAddCommandContract:
    """Test add command follows the CLI interface contract."""

    def setup_method(self):
        """Set up authenticated session for each test."""
        # Initialize and authenticate
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

    def test_add_command_basic_usage(self):
        """Test basic add command stores password successfully."""
        # This test MUST fail until implementation exists
        result = subprocess.run(
            ['localpass', 'add', 'gmail', '--username', 'test@example.com'],
            capture_output=True,
            text=True,
            input='mypassword123\n'
        )
        
        assert result.returncode == 0
        assert "✓ Password for gmail added successfully" in result.stdout
        assert "Service: gmail" in result.stdout
        assert "Username: test@example.com" in result.stdout
        assert "Strength:" in result.stdout

    def test_add_command_json_format(self):
        """Test add command with JSON output format."""
        result = subprocess.run(
            ['localpass', 'add', 'github', '--username', 'testuser', '--format', 'json'],
            capture_output=True,
            text=True,
            input='mypassword123\n'
        )
        
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output['status'] == 'success'
        assert output['action'] == 'add'
        assert output['service'] == 'github'
        assert output['username'] == 'testuser'
        assert 'entry_id' in output
        assert 'password_strength' in output

    def test_add_command_with_generate(self):
        """Test add command with password generation."""
        result = subprocess.run(
            ['localpass', 'add', 'aws', '--username', 'admin', '--generate'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "✓ Generated secure password" in result.stdout
        assert "✓ Password for aws added successfully" in result.stdout
        assert "Generated:" in result.stdout

    def test_add_command_with_generate_custom_length(self):
        """Test add command with custom generated password length."""
        result = subprocess.run(
            ['localpass', 'add', 'aws', '--username', 'admin', '--generate', '--length', '24'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        # Generated password should be visible in output
        lines = result.stdout.split('\n')
        generated_line = [line for line in lines if 'Generated:' in line][0]
        password = generated_line.split('Generated:')[1].strip()
        assert len(password) == 24

    def test_add_command_with_url_and_notes(self):
        """Test add command with optional URL and notes."""
        result = subprocess.run([
            'localpass', 'add', 'mybank', 
            '--username', 'customer123',
            '--url', 'https://mybank.com',
            '--notes', 'Personal banking account'
        ], capture_output=True, text=True, input='bankpass456\n')
        
        assert result.returncode == 0
        assert "✓ Password for mybank added successfully" in result.stdout

    def test_add_command_duplicate_service_username(self):
        """Test add command fails for duplicate service/username combination."""
        # Add first entry
        subprocess.run(
            ['localpass', 'add', 'gmail', '--username', 'test@example.com'],
            capture_output=True,
            text=True,
            input='password1\n'
        )
        
        # Try to add duplicate
        result = subprocess.run(
            ['localpass', 'add', 'gmail', '--username', 'test@example.com'],
            capture_output=True,
            text=True,
            input='password2\n'
        )
        
        assert result.returncode == 4  # Validation error exit code
        assert "already exists" in result.stderr or "duplicate" in result.stderr

    def test_add_command_missing_username(self):
        """Test add command fails when username is not provided."""
        result = subprocess.run(
            ['localpass', 'add', 'gmail'],
            capture_output=True,
            text=True,
            input='mypassword123\n'
        )
        
        assert result.returncode != 0
        assert "username" in result.stderr or "required" in result.stderr

    def test_add_command_invalid_service_name(self):
        """Test add command validates service name format."""
        result = subprocess.run(
            ['localpass', 'add', 'a' * 101, '--username', 'test'],  # Too long
            capture_output=True,
            text=True,
            input='password123\n'
        )
        
        assert result.returncode == 4  # Validation error
        assert "invalid" in result.stderr or "length" in result.stderr

    def test_add_command_no_authentication(self):
        """Test add command fails when user is not authenticated."""
        # Clear any existing session (logout)
        subprocess.run(['localpass', 'logout'], capture_output=True)
        
        result = subprocess.run(
            ['localpass', 'add', 'gmail', '--username', 'test@example.com'],
            capture_output=True,
            text=True,
            input='password123\n'
        )
        
        assert result.returncode == 2  # Authentication error
        assert "not authenticated" in result.stderr or "login required" in result.stderr

    def test_add_command_help(self):
        """Test add command shows help information."""
        result = subprocess.run(
            ['localpass', 'add', '--help'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "Add a new password entry" in result.stdout
        assert "--username" in result.stdout
        assert "--generate" in result.stdout
        assert "--length" in result.stdout
        assert "--url" in result.stdout
        assert "--notes" in result.stdout

    def test_add_command_quiet_mode(self):
        """Test add command with --quiet flag suppresses non-essential output."""
        result = subprocess.run(
            ['localpass', 'add', 'gmail', '--username', 'test@example.com', '--quiet'],
            capture_output=True,
            text=True,
            input='mypassword123\n'
        )
        
        assert result.returncode == 0
        # Quiet mode should have minimal output
        assert len(result.stdout.strip()) < 50