# Signed by JOE
"""Safe password-file handling for the local authentication tester.

Reads a UTF-8 ``.txt`` file of candidate passwords used against a *local
loopback* mock application only. Every non-empty line is processed exactly
once, in file order. Blank lines are ignored; password content is preserved
without extra normalization beyond removing line terminators.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List


class PasswordFileError(Exception):
    """Raised when the password file is invalid or unreadable."""
    pass


@dataclass
class PasswordFileResult:
    """Result of reading and validating the password file."""
    passwords: List[str]
    count: int
    source_path: str


def read_password_file(file_path: str | Path) -> PasswordFileResult:
    """Read all non-empty password entries from the file.

    - Accepts UTF-8 ``.txt`` files.
    - Handles Windows (CRLF), Unix (LF) and lone-CR line endings.
    - A line counts as blank when it is empty or contains only whitespace;
      such lines are ignored. All other lines are kept in their original
      order and content (line terminators only are removed by splitlines()).
    - Passwords are never printed, logged, or written to any report by this
      function.

    Args:
        file_path: Path to the password file.

    Returns:
        PasswordFileResult with the full ordered list of passwords.

    Raises:
        PasswordFileError: If the file is missing, unreadable, not a regular
            file, not valid UTF-8, or contains no non-empty entries.
    """
    path = Path(file_path)

    if not path.exists():
        raise PasswordFileError(
            f"Password file not found: {file_path}. "
            f"Create one with one password per line."
        )

    if not path.is_file():
        raise PasswordFileError(f"Password path is not a regular file: {file_path}")

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise PasswordFileError(f"Password file must be UTF-8 encoded: {e}")
    except OSError as e:
        raise PasswordFileError(f"Could not read password file '{file_path}': {e}")

    # splitlines() handles '\n', '\r\n' and '\r' and strips the terminators.
    passwords: List[str] = []
    for line in content.splitlines():
        # Skip blank lines (empty or whitespace-only) but otherwise keep the
        # exact content so valid passwords are not corrupted by over-normalizing.
        if not line.strip():
            continue
        passwords.append(line)

    if not passwords:
        raise PasswordFileError(
            f"Password file '{file_path}' contains no non-empty password entries."
        )

    return PasswordFileResult(
        passwords=passwords,
        count=len(passwords),
        source_path=str(path),
    )


def validate_password_file(file_path: str | Path) -> None:
    """Pre-flight validation without returning any password values.

    Args:
        file_path: Path to the password file.

    Raises:
        PasswordFileError: If the file is missing, empty, or unreadable.
    """
    read_password_file(file_path)


def create_example_password_file(output_path: str | Path) -> None:
    """Create an example password file with usage instructions."""
    content = """# Password file for authorized authentication testing.
#
# INSTRUCTIONS:
#   1. Rename this file to 'password.txt' (or point config.json at it).
#   2. Put one candidate password per line.
#   3. Every non-empty line is processed once, in order. Blank lines are
#      ignored. Order is preserved.
#   4. Only test hosts listed in allowed_hosts that you own / are authorized
#      to test, using a dedicated test account you control.
#   5. Never commit real passwords to version control (password.txt is
#      gitignored).
#
# Sample candidate list (replace with your own test values):
# MyFirstTestPassword
# MySecondTestPassword
"""
    Path(output_path).write_text(content, encoding="utf-8")
