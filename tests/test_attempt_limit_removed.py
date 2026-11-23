# Signed by JOE
"""Guard test: the obsolete 'Max Attempts' setting must not exist anywhere.

Scans the project's own source/config/docs files (excluding the virtualenv,
caches, and generated egg-info) for forbidden attempt-limit tokens and fails
if any remain.
"""

import os
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Tokens that would indicate a reintroduced attempt-count limit.
FORBIDDEN_TOKENS = [
    "max_attempts",
    "Max Attempts",
    "maxAttempts",
    "maximum_attempts",
    "Maximum Attempts",
    "maximumAttempts",
]

# Directories / names to skip while scanning.
_SKIP_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", ".git",
              "node_modules", "reports", "build", "dist"}
_SKIP_SUFFIX = {".pyc", ".pyo", ".egg", ".log"}


def _iter_source_files():
    """Yield only the project's own source/config/doc files.

    Unit tests are intentionally excluded: they legitimately reference the
    forbidden tokens to assert their *absence*. This scan proves no real
    configuration or source usage remains.
    """
    root_files = {"README.md", "tester.py", "pyproject.toml"}
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS
                   and not d.endswith(".egg-info")]
        for name in files:
            if any(name.endswith(sfx) for sfx in _SKIP_SUFFIX):
                continue
            abs_path = os.path.join(root, name)
            rel = os.path.relpath(abs_path, PROJECT_ROOT).replace("\\", "/")

            in_src = rel.startswith("src/")
            is_root_config_or_doc = (
                os.path.dirname(rel) == "" and name.endswith((".json", ".md", ".toml"))
            )
            is_root_script = os.path.dirname(rel) == "" and name in root_files

            if in_src or is_root_config_or_doc or is_root_script:
                yield abs_path


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, OSError):
        return ""


def _rel(path):
    return os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")


def test_no_attempt_limit_tokens_in_source():
    """No forbidden attempt-limit token appears in any project source file."""
    offenders = []
    for path in _iter_source_files():
        content = _read(path)
        for token in FORBIDDEN_TOKENS:
            if token in content:
                offenders.append(f"{_rel(path)} -> {token}")

    assert not offenders, (
        "Obsolete attempt-limit settings found:\n  " + "\n  ".join(offenders)
    )


def test_appconfig_has_no_attempt_fields():
    from auth_audit.config import AppConfig
    fields = set(AppConfig.model_fields.keys())
    assert not (fields & {"maximum_attempts", "max_attempts", "execution_mode"})


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
