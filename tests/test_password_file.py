"""Unit tests for password file handling."""

import pytest
from pathlib import Path

from auth_audit.password_handler import (
    read_password_file,
    validate_password_file_for_mode,
    create_example_password_file,
    PasswordFileError,
    PasswordFileResult,
)


class TestPasswordFileReading:
    """Tests for password file reading and validation."""
    
    def test_read_single_password_production(self, tmp_path):
        """Test reading a single password for production mode."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("MySecurePassword123!\n", encoding="utf-8")
        
        result = read_password_file(password_file, "production", 1)
        
        assert isinstance(result, PasswordFileResult)
        assert result.count == 1
        assert result.passwords == ["MySecurePassword123!"]
        assert result.mode == "production"
        assert result.max_allowed == 1
    
    def test_read_password_with_whitespace(self, tmp_path):
        """Test that whitespace is stripped from passwords."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("  MyPassword  \n", encoding="utf-8")
        
        result = read_password_file(password_file, "production", 1)
        
        assert result.passwords == ["MyPassword"]
    
    def test_read_password_windows_line_endings(self, tmp_path):
        """Test handling of Windows line endings (CRLF)."""
        password_file = tmp_path / "password.txt"
        password_file.write_bytes(b"Password1\r\n")
        
        result = read_password_file(password_file, "production", 1)
        
        assert result.passwords == ["Password1"]
    
    def test_read_password_mixed_line_endings(self, tmp_path):
        """Test handling of mixed line endings."""
        password_file = tmp_path / "password.txt"
        password_file.write_bytes(b"Password1\r\nPassword2\n")
        
        result = read_password_file(password_file, "staging", 5)
        
        assert result.passwords == ["Password1", "Password2"]
    
    def test_read_password_ignores_blank_lines(self, tmp_path):
        """Test that blank lines are ignored."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("\n\nPassword1\n\n\n", encoding="utf-8")
        
        result = read_password_file(password_file, "production", 1)
        
        assert result.passwords == ["Password1"]
    
    def test_read_password_utf8(self, tmp_path):
        """Test UTF-8 encoded passwords."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("Pässwörd🔒\n", encoding="utf-8")
        
        result = read_password_file(password_file, "production", 1)
        
        assert result.passwords == ["Pässwörd🔒"]
    
    def test_production_mode_requires_exactly_one_password(self, tmp_path):
        """Test that production mode requires exactly one password."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("Password1\nPassword2\n", encoding="utf-8")
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "production", 1)
        
        assert "Exactly one password required" in str(exc.value)
        assert "found 2" in str(exc.value)
    
    def test_production_mode_rejects_empty_file(self, tmp_path):
        """Test that production mode rejects empty password file."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("\n\n\n", encoding="utf-8")
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "production", 1)
        
        assert "no non-empty passwords" in str(exc.value)
    
    def test_staging_mode_allows_multiple_passwords(self, tmp_path):
        """Test that staging mode allows multiple passwords up to limit."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("Password1\nPassword2\nPassword3\n", encoding="utf-8")
        
        result = read_password_file(password_file, "staging", 5)
        
        assert result.count == 3
        assert result.max_allowed == 5
        assert result.passwords == ["Password1", "Password2", "Password3"]
    
    def test_staging_mode_enforces_max_attempts(self, tmp_path):
        """Test that staging mode enforces maximum attempts limit."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("P1\nP2\nP3\nP4\nP5\n", encoding="utf-8")
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "staging", 3)
        
        assert "Too many passwords" in str(exc.value)
        assert "Maximum allowed: 3" in str(exc.value)
    
    def test_staging_mode_requires_at_least_one(self, tmp_path):
        """Test that staging mode requires at least one password."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("", encoding="utf-8")
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "staging", 5)
        
        assert "no non-empty passwords" in str(exc.value)
    
    def test_nonexistent_file_raises_error(self, tmp_path):
        """Test that nonexistent file raises error."""
        password_file = tmp_path / "nonexistent.txt"
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "production", 1)
        
        assert "not found" in str(exc.value)
    
    def test_directory_instead_of_file_raises_error(self, tmp_path):
        """Test that directory path raises error."""
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(tmp_path, "production", 1)
        
        assert "not a file" in str(exc.value)
    
    def test_invalid_encoding_raises_error(self, tmp_path):
        """Test that non-UTF-8 file raises error."""
        password_file = tmp_path / "password.txt"
        password_file.write_bytes(b"\xff\xfe")  # Invalid UTF-8
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "production", 1)
        
        assert "UTF-8 encoded" in str(exc.value)
    
    def test_unknown_execution_mode_raises_error(self, tmp_path):
        """Test that unknown execution mode raises error."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("Password1\n", encoding="utf-8")
        
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(password_file, "unknown", 1)
        
        assert "Unknown execution mode" in str(exc.value)


class TestPasswordFileValidation:
    """Tests for password file validation without returning passwords."""
    
    def test_validate_production_mode(self, tmp_path):
        """Test validation for production mode."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("Password1\n", encoding="utf-8")
        
        # Should not raise
        validate_password_file_for_mode(password_file, "production", 1)
    
    def test_validate_staging_mode(self, tmp_path):
        """Test validation for staging mode."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("Password1\nPassword2\n", encoding="utf-8")
        
        # Should not raise
        validate_password_file_for_mode(password_file, "staging", 5)


class TestExamplePasswordFile:
    """Tests for example password file creation."""
    
    def test_create_example_password_file(self, tmp_path):
        """Test creating example password file."""
        output_path = tmp_path / "password.txt.example"
        create_example_password_file(output_path)
        
        assert output_path.exists()
        
        content = output_path.read_text(encoding="utf-8")
        assert "INSTRUCTIONS" in content
        assert "PRODUCTION mode" in content
        assert "STAGING mode" in content
        assert "MySecureTestPassword123!" in content
        assert ".gitignore" in content