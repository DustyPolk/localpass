"""Integration tests for the initialization flow.

These tests verify the complete initialization workflow.
They MUST fail before implementation exists (TDD requirement).
"""
import json
import subprocess
import pytest
from pathlib import Path
import tempfile
import shutil


class TestInitializationFlow:
    """Test complete initialization workflow integration."""

    def setup_method(self):
        """Set up temporary directory for each test."""
        self.temp_dir = Path(tempfile.mkdtemp())
        # Set custom data directory to avoid conflicts
        self.env = {'LOCALPASS_DATA_DIR': str(self.temp_dir)}

    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_full_initialization_workflow(self):
        """Test complete initialization workflow from start to finish."""
        # This test MUST fail until implementation exists
        
        # Step 1: Initialize password manager
        init_result = subprocess.run(
            ['localpass', 'init', '--username', 'testuser'],
            capture_output=True,
            text=True,
            input='securepassword123\nsecurepassword123\n',
            env=self.env
        )
        
        assert init_result.returncode == 0
        assert "✓ Password manager initialized successfully" in init_result.stdout
        
        # Step 2: Verify database file was created
        db_path = self.temp_dir / "passwords.db"
        assert db_path.exists()
        
        # Step 3: Authenticate with master password
        auth_result = subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='securepassword123\n',
            env=self.env
        )
        
        assert auth_result.returncode == 0
        assert "✓ Authenticated successfully" in auth_result.stdout
        
        # Step 4: Verify we can now perform authenticated operations
        add_result = subprocess.run(
            ['localpass', 'add', 'testservice', '--username', 'testuser'],
            capture_output=True,
            text=True,
            input='testpassword123\n',
            env=self.env
        )
        
        assert add_result.returncode == 0

    def test_initialization_creates_proper_database_schema(self):
        """Test initialization creates database with correct schema."""
        # Initialize
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='securepassword123\nsecurepassword123\n',
            env=self.env
        )
        
        # Verify database schema using SQLite CLI
        db_path = self.temp_dir / "passwords.db"
        assert db_path.exists()
        
        # Check that required tables exist
        result = subprocess.run(
            ['sqlite3', str(db_path), '.schema'],
            capture_output=True,
            text=True
        )
        
        schema = result.stdout
        assert 'CREATE TABLE master_credential' in schema
        assert 'CREATE TABLE password_entries' in schema
        assert 'CREATE TABLE database_metadata' in schema

    def test_initialization_encrypts_database_properly(self):
        """Test that initialization properly encrypts sensitive data."""
        # Initialize and authenticate
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='securepassword123\nsecurepassword123\n',
            env=self.env
        )
        subprocess.run(
            ['localpass', 'auth'],
            capture_output=True,
            text=True,
            input='securepassword123\n',
            env=self.env
        )
        
        # Add a password entry
        subprocess.run(
            ['localpass', 'add', 'testservice', '--username', 'testuser'],
            capture_output=True,
            text=True,
            input='plaintextpassword\n',
            env=self.env
        )
        
        # Examine database directly to ensure password is encrypted
        db_path = self.temp_dir / "passwords.db"
        result = subprocess.run(
            ['sqlite3', str(db_path), 'SELECT encrypted_password FROM password_entries LIMIT 1;'],
            capture_output=True,
            text=True
        )
        
        encrypted_data = result.stdout.strip()
        # Should be JSON with encryption fields, not plaintext
        assert 'plaintextpassword' not in encrypted_data
        assert 'nonce' in encrypted_data
        assert 'ciphertext' in encrypted_data
        assert 'tag' in encrypted_data

    def test_cross_platform_initialization(self):
        """Test initialization works correctly across different platforms."""
        # This should work regardless of platform
        result = subprocess.run(
            ['localpass', 'init', '--format', 'json'],
            capture_output=True,
            text=True,
            input='testpassword123\ntestpassword123\n',
            env=self.env
        )
        
        assert result.returncode == 0
        output = json.loads(result.stdout)
        
        # Verify platform-appropriate database path
        db_path = Path(output['database_path']).expanduser()
        assert db_path.exists()
        
        # Path should be within our temp directory
        assert str(self.temp_dir) in str(db_path)

    def test_initialization_security_validation(self):
        """Test initialization properly validates security requirements."""
        # Test weak password rejection
        weak_result = subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='123\n123\n',  # Too weak
            env=self.env
        )
        
        assert weak_result.returncode != 0
        assert "weak" in weak_result.stderr or "short" in weak_result.stderr
        
        # Verify no database was created for failed init
        db_path = self.temp_dir / "passwords.db"
        assert not db_path.exists()

    def test_re_initialization_protection(self):
        """Test that re-initialization is properly protected."""
        # First initialization
        subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='firstpassword123\nfirstpassword123\n',
            env=self.env
        )
        
        # Second initialization should fail without --force
        second_result = subprocess.run(
            ['localpass', 'init'],
            capture_output=True,
            text=True,
            input='secondpassword456\nsecondpassword456\n',
            env=self.env
        )
        
        assert second_result.returncode != 0
        assert "already" in second_result.stderr
        
        # But should work with --force
        force_result = subprocess.run(
            ['localpass', 'init', '--force'],
            capture_output=True,
            text=True,
            input='newpassword789\nnewpassword789\n',
            env=self.env
        )
        
        assert force_result.returncode == 0