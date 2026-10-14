"""Safe password file handling for authentication testing.

This module provides secure password file reading with strict validation
to prevent brute-force attempts and enforce security policies.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List


class PasswordFileError(Exception):
    """Raised when password file validation fails."""
    pass


@dataclass
class PasswordFileResult:
    """Result of password file validation and reading."""
    passwords: List[str]
    count: int
    mode: str
    max_allowed: int


def read_password_file(
    file_path: str | Path,
    execution_mode: str,
    maximum_attempts: int
) -> PasswordFileResult:
    """Read and validate password file based on execution mode.
    
    Args:
        file_path: Path to the password file.
        execution_mode: Either 'production' or 'staging'.
        maximum_attempts: Maximum number of attempts allowed (staging mode).
        
    Returns:
        PasswordFileResult with validated passwords.
        
    Raises:
        PasswordFileError: If validation fails.
    """
    path = Path(file_path)
    
    if not path.exists():
        raise PasswordFileError(
            f"Password file not found: {file_path}. "
            f"Create it from password.txt.example and add your test password."
        )
    
    if not path.is_file():
        raise PasswordFileError(f"Password path is not a file: {file_path}")
    
    # Read file with UTF-8 encoding, handle Windows line endings
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise PasswordFileError(f"Password file must be UTF-8 encoded: {e}")
    
    # Split lines, strip whitespace, filter empty lines
    lines = content.splitlines()
    passwords = [line.strip() for line in lines if line.strip()]
    
    if not passwords:
        raise PasswordFileError(
            "Password file contains no non-empty passwords. "
            "Add exactly one password for production mode."
        )
    
    # Validate based on execution mode
    if execution_mode == "production":
        if len(passwords) != 1:
            raise PasswordFileError(
                f"PRODUCTION MODE: Exactly one password required, "
                f"found {len(passwords)}. "
                f"Remove extra lines or use staging mode for multiple passwords."
            )
        max_allowed = 1
    elif execution_mode == "staging":
        if len(passwords) > maximum_attempts:
            raise PasswordFileError(
                f"STAGING MODE: Too many passwords ({len(passwords)}). "
                f"Maximum allowed: {maximum_attempts}. "
                f"Reduce the password list or increase maximum_attempts in config."
            )
        if len(passwords) < 1:
            raise PasswordFileError(
                "STAGING MODE: At least one password required."
            )
        max_allowed = maximum_attempts
    else:
        raise PasswordFileError(f"Unknown execution mode: {execution_mode}")
    
    return PasswordFileResult(
        passwords=passwords,
        count=len(passwords),
        mode=execution_mode,
        max_allowed=max_allowed
    )


def validate_password_file_for_mode(
    file_path: str | Path,
    execution_mode: str,
    maximum_attempts: int
) -> None:
    """Validate password file without returning passwords.
    
    Useful for pre-flight checks before launching browser.
    
    Args:
        file_path: Path to the password file.
        execution_mode: Either 'production' or 'staging'.
        maximum_attempts: Maximum number of attempts allowed.
        
    Raises:
        PasswordFileError: If validation fails.
    """
    read_password_file(file_path, execution_mode, maximum_attempts)


def create_example_password_file(output_path: str | Path) -> None:
    """Create an example password file with instructions.
    
    Args:
        output_path: Path where the example file should be written.
    """
    content = """# Password file for authentication testing
#
# INSTRUCTIONS:
# 1. Rename this file to 'password.txt' (or update config.json to point to your file)
# 2. Place exactly ONE test password on a single line for PRODUCTION mode
# 3. For STAGING mode, you may include up to MAXIMUM_ATTEMPTS passwords (one per line)
# 4. Never commit real passwords to version control
# 5. This file should be listed in .gitignore
#
# Example for PRODUCTION mode (single password):
# MySecureTestPassword123!
#
# Example for STAGING mode (multiple passwords, requires explicit opt-in):
# Password1
# Password2
# Password3
"""
    Path(output_path).write_text(content, encoding="utf-8")