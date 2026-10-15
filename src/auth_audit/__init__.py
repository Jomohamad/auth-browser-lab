# Signed by JOE
"""Authentication Audit Tool - Core Modules

This package contains the core modules for the authorized authentication
testing tool:

- config: configuration model, validation, safety policy, persistence
- password_handler: safe password-file handling (no attempt limit)
- security: security-challenge detection
- result_classifier: explicit result classification
- reporting: sanitized CSV reporting (no secrets)
- browser: low-level Playwright launch + selector diagnostics
- auth_flow: the authentication testing orchestration + run policy
- schema: declarative configuration schema (all fields)
- credentials: secret resolution (env / Credential Manager / prompt)
- dependency_manager: dependency/tool diagnostics + controlled updates
- windows_console: best-effort Windows console always-on-top
- cli: command-line interface
- settings_tui: interactive Textual settings TUI
"""

__version__ = "1.1.0"
__author__ = "JOE"
