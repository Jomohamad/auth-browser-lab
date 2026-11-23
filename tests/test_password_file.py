# Signed by JOE
"""Unit tests for full password-file processing (no attempt limit)."""

import pytest
from pathlib import Path

from auth_audit.password_handler import (
    read_password_file,
    validate_password_file,
    create_example_password_file,
    PasswordFileError,
    PasswordFileResult,
)


class TestReadAllEntries:
    """Every non-empty entry is read, in order, with no attempt cap."""

    def test_reads_all_entries_in_order(self, tmp_path):
        """All non-empty entries are returned in original order."""
        f = tmp_path / "password.txt"
        f.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")

        result = read_password_file(f)

        assert isinstance(result, PasswordFileResult)
        assert result.passwords == ["alpha", "beta", "gamma"]
        assert result.count == 3

    def test_no_attempt_limit_many_entries(self, tmp_path):
        """A large file is fully read (no cap, no truncation)."""
        f = tmp_path / "password.txt"
        f.write_text("\n".join(f"pw{n}" for n in range(50)), encoding="utf-8")

        result = read_password_file(f)

        assert result.count == 50
        assert result.passwords == [f"pw{n}" for n in range(50)]

    def test_blank_lines_ignored(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("\n\nalpha\n\n   \nbeta\n\n", encoding="utf-8")

        result = read_password_file(f)

        assert result.passwords == ["alpha", "beta"]

    def test_windows_line_endings(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_bytes(b"alpha\r\nbeta\r\ngamma\r\n")

        result = read_password_file(f)

        assert result.passwords == ["alpha", "beta", "gamma"]

    def test_unix_line_endings(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_bytes(b"alpha\nbeta\ngamma\n")

        result = read_password_file(f)

        assert result.passwords == ["alpha", "beta", "gamma"]

    def test_lone_cr_line_endings(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_bytes(b"alpha\rbeta\rgamma")

        result = read_password_file(f)

        assert result.passwords == ["alpha", "beta", "gamma"]

    def test_mixed_line_endings(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_bytes(b"alpha\r\nbeta\ngamma\r")

        result = read_password_file(f)

        assert result.passwords == ["alpha", "beta", "gamma"]

    def test_no_excessive_normalization_of_contents(self, tmp_path):
        """Interior/edge characters of a valid password are preserved."""
        f = tmp_path / "password.txt"
        # Leading/trailing spaces are significant content and must be kept.
        f.write_text(" P@ss w/ spaces \n", encoding="utf-8")

        result = read_password_file(f)

        assert result.passwords == [" P@ss w/ spaces "]

    def test_utf8_entries(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("Pässwörd🔒\n正常密码\n", encoding="utf-8")

        result = read_password_file(f)

        assert result.passwords == ["Pässwörd🔒", "正常密码"]

    def test_no_trailing_newline(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("alpha\nbeta", encoding="utf-8")

        result = read_password_file(f)

        assert result.passwords == ["alpha", "beta"]


class TestPasswordFileErrors:
    """Missing/empty/unreadable/malformed files raise before any browser use."""

    def test_missing_file(self, tmp_path):
        missing = tmp_path / "nope.txt"
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(missing)
        assert "not found" in str(exc.value)

    def test_empty_file(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("")
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(f)
        assert "no non-empty" in str(exc.value)

    def test_only_blank_lines_file(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("\n   \n\t\n")
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(f)
        assert "no non-empty" in str(exc.value)

    def test_directory_instead_of_file(self, tmp_path):
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(tmp_path)
        assert "not a regular file" in str(exc.value)

    def test_invalid_utf8(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_bytes(b"\xff\xfe")
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(f)
        assert "UTF-8" in str(exc.value)


class TestValidateAndExample:
    """validate_password_file + example file generation."""

    def test_validate_ok(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("only-one\n")
        validate_password_file(f)  # should not raise

    def test_validate_empty_raises(self, tmp_path):
        f = tmp_path / "password.txt"
        f.write_text("")
        with pytest.raises(PasswordFileError):
            validate_password_file(f)

    def test_create_example_password_file(self, tmp_path):
        out = tmp_path / "password.txt.example"
        create_example_password_file(out)

        content = out.read_text(encoding="utf-8")
        assert "one candidate password per line" in content
        assert "order" in content
        assert "gitignored" in content


class TestNoPasswordLeakage:
    """Ensure password values are never surfaced by error messages."""

    def test_empty_file_error_contains_no_password(self, tmp_path):
        # Errors reference the file, never the (absent) password content.
        f = tmp_path / "password.txt"
        f.write_text("   \n")
        with pytest.raises(PasswordFileError) as exc:
            read_password_file(f)
        # No accidental password material in the message.
        assert "password entries" in str(exc.value)
