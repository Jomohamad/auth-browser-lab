# Signed by JOE
"""Configuration management for the authentication testing tool.

This module handles loading, validating, and persisting the application
configuration. It supports loading from JSON configuration files and
environment variables, and enforces a strict safety policy:

  * An explicit ``allowed_hosts`` allowlist — you declare the hosts you may test.
  * HTTPS required for non-local hosts (HTTP only for loopback targets).
  * Passwords/tokens are never written into the JSON configuration file.
"""

import ipaddress
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class ConfigError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


def is_local_hostname(hostname: str) -> bool:
    """Return True for local loopback targets.

    Recognizes ``localhost``, IPv6 loopback ``::1`` and the ``127.0.0.0/8``
    range. Used only to exempt loopback development targets from the HTTPS
    requirement.
    """
    if not hostname:
        return False
    host = hostname.lower()

    if host == "localhost" or host == "::1":
        return True

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False

    return addr.is_loopback


# Backwards-compatible alias used by callers that phrase this as "loopback".
is_loopback_host = is_local_hostname


def hostname_of(url: str) -> str:
    """Return the lower-cased hostname of a URL (empty string if none)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""
    return parsed.hostname.lower() if parsed.hostname else ""


class AuthenticationProvider(str, Enum):
    """Supported authentication providers."""
    CUSTOM = "custom"
    AUTHJS = "authjs"
    NEXT_AUTH = "nextauth"
    CLERK = "clerk"
    SUPABASE = "supabase"


# Adapter notes for providers referenced by the settings UI. Each provider has
# different login-form and navigation behavior; the tool never assumes a single
# shape. These are exposed for documentation/selection in the settings TUI.
AUTH_PROVIDER_NOTES = {
    AuthenticationProvider.CUSTOM: "You supply all selectors and indicators.",
    AuthenticationProvider.AUTHJS: (
        "Auth.js/NextAuth credential login. Typically posts to "
        "/api/auth/callback/credentials and sets a session cookie; success is a "
        "redirect to a callback URL (e.g. /dashboard) with no error element."
    ),
    AuthenticationProvider.NEXT_AUTH: "Alias of Auth.js/NextAuth credential flow.",
    AuthenticationProvider.CLERK: (
        "Clerk uses a hosted/sign-in component. Configure the email field, "
        "continue/password step selectors, and the post-sign-in URL."
    ),
    AuthenticationProvider.SUPABASE: (
        "Supabase Auth. Configure email/password fields and the redirectTo; "
        "success is a navigation to an authenticated route with a valid session."
    ),
}


class ResultCategory(str, Enum):
    """Result classification categories."""
    SUCCESS_CONFIRMED = "SUCCESS_CONFIRMED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    LOGIN_PAGE_NOT_FOUND = "LOGIN_PAGE_NOT_FOUND"
    SELECTOR_NOT_FOUND = "SELECTOR_NOT_FOUND"
    FORM_NOT_READY = "FORM_NOT_READY"
    STOPPED_SECURITY_CHALLENGE = "STOPPED_SECURITY_CHALLENGE"
    STOPPED_RATE_LIMIT = "STOPPED_RATE_LIMIT"
    STOPPED_ACCESS_DENIED = "STOPPED_ACCESS_DENIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    NAVIGATION_ERROR = "NAVIGATION_ERROR"
    UNAUTHORIZED_HOST_BLOCKED = "UNAUTHORIZED_HOST_BLOCKED"


class BrowserType(str, Enum):
    """Supported browser types."""
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


class SecurityChallengeConfig(BaseModel):
    """Configuration for security challenge detection."""
    http_status_codes: list[int] = Field(
        default=[403, 429],
        description="HTTP status codes that indicate a security challenge"
    )
    blocking_text_patterns: list[str] = Field(
        default=[
            "too many attempts",
            "too many requests",
            "rate limit",
            "captcha",
            "temporarily blocked",
            "try again later",
            "account locked",
            "access denied",
            "blocked",
            "suspicious activity",
            "verify you are human",
        ],
        description="Text patterns that indicate blocking or challenges"
    )
    captcha_selectors: list[str] = Field(
        default=[
            "[data-testid*='captcha']",
            "[id*='captcha']",
            "[class*='captcha']",
            "iframe[src*='recaptcha']",
            "iframe[src*='hcaptcha']",
            ".g-recaptcha",
            "#h-captcha",
        ],
        description="CSS selectors for CAPTCHA elements"
    )
    mfa_selectors: list[str] = Field(
        default=[
            "[data-testid*='mfa']",
            "[data-testid*='2fa']",
            "[id*='mfa']",
            "[id*='2fa']",
            ".mfa-challenge",
            ".two-factor",
        ],
        description="CSS selectors for MFA/2FA challenge elements"
    )


class AuthConfig(BaseModel):
    """Authentication-specific configuration.

    The login-form shape differs per provider (see AUTH_PROVIDER_NOTES). All
    fields are operator-supplied because the tool never assumes a common form.
    """
    provider: AuthenticationProvider = Field(
        default=AuthenticationProvider.CUSTOM,
        description="Authentication provider type"
    )
    username: str = Field(
        default="",
        description="Test account username/email (non-secret identifier)"
    )
    # NOTE: a password is intentionally NOT a stored config field. Secrets are
    # resolved at run time from the environment, Windows Credential Manager, or
    # an interactive prompt and are never written to the JSON config.
    username_selector: str = Field(
        default="input[name=\"email\"]",
        description="CSS selector for username/email field"
    )
    password_selector: str = Field(
        default="input[name=\"password\"]",
        description="CSS selector for password field"
    )
    submit_selector: str = Field(
        default="button[type=\"submit\"]",
        description="CSS selector for submit button"
    )
    success_url_patterns: list[str] = Field(
        default=["/dashboard", "/home", "/app"],
        description="URL patterns that indicate successful authentication"
    )
    success_selectors: list[str] = Field(
        default=[
            "[data-testid=\"user-menu\"]",
            ".user-profile",
            "a[href*=\"logout\"]"
        ],
        description="CSS selectors that indicate authenticated state"
    )
    failure_selectors: list[str] = Field(
        default=[
            "[data-testid=\"error-message\"]",
            ".auth-error",
            ".alert-danger"
        ],
        description="CSS selectors for authentication failure messages"
    )
    success_on_navigation_without_failure: bool = Field(
        default=False,
        description=(
            "Operator-defined success signal for apps where the login error "
            "element is the sole correctness indicator. When enabled, a submit "
            "that navigates off the login page with NO failure indicator is "
            "classified as SUCCESS_CONFIRMED. A redirect that stays on the "
            "login page (or shows a failure element) is never success."
        )
    )


class BrowserConfig(BaseModel):
    """Browser configuration."""
    browser: BrowserType = Field(
        default=BrowserType.CHROMIUM,
        description="Browser to use for testing"
    )
    headless: bool = Field(
        default=False,
        description="Run browser in headless mode"
    )
    navigation_timeout_ms: int = Field(
        default=15000,
        description="Navigation timeout in milliseconds"
    )
    delay_before_submit_seconds: float = Field(
        default=3.0,
        description="Delay before submitting the login form"
    )
    inter_entry_delay_seconds: float = Field(
        default=0.0,
        description="Optional pacing delay between candidate entries"
    )
    viewport_width: int = Field(
        default=1280,
        description="Viewport width in pixels"
    )
    viewport_height: int = Field(
        default=720,
        description="Viewport height in pixels"
    )


class ReportConfig(BaseModel):
    """Reporting configuration."""
    report_directory: str = Field(
        default="reports",
        description="Directory for CSV reports"
    )
    timestamp_format: str = Field(
        default="%Y-%m-%dT%H:%M:%S%z",
        description="strftime format for report/log timestamps"
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )
    retention_days: int = Field(
        default=0,
        description="Delete report CSV files older than N days (0 = keep all)"
    )
    diagnostic_verbosity: str = Field(
        default="normal",
        description="Diagnostic verbosity: minimal | normal | verbose"
    )


class AppConfig(BaseModel):
    """Main application configuration."""
    target_url: str = Field(
        description="Target login URL"
    )
    allowed_hosts: list[str] = Field(
        default=[],
        description="Allowed hostnames for testing"
    )
    auth: AuthConfig = Field(default_factory=AuthConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    security: SecurityChallengeConfig = Field(default_factory=SecurityChallengeConfig)
    stop_on_security_challenge: bool = Field(
        default=True,
        description="Stop immediately when security challenge detected"
    )
    always_on_top: bool = Field(
        default=False,
        description="Best-effort Windows console always-on-top (opt-in)"
    )
    password_file: str = Field(
        default="password.txt",
        description="Path to password file (every non-empty line is processed)"
    )
    include_password_in_report: bool = Field(
        default=False,
        description=(
            "Operator opt-in (for their own local, gitignored report only): "
            "when True the candidate password is written to a dedicated CSV "
            "column. Disabled by default so reports stay secret-free."
        )
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        """Validate target URL format."""
        if not v:
            raise ValueError("target_url is required")
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("target_url must be a valid URL with scheme and host")
        return v

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, v: list[str]) -> list[str]:
        """Validate allowed hosts list."""
        if not v:
            raise ValueError("allowed_hosts must contain at least one host")
        return [host.lower() for host in v]

    @model_validator(mode="after")
    def validate_hostname_match(self) -> "AppConfig":
        """Validate that the target host is allowlisted and HTTPS enforced.

        The operator declares the hosts they are authorized to test via
        ``allowed_hosts``. HTTPS is required for every non-local host; HTTP is
        permitted only for explicit localhost development targets.
        """
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        if hostname not in self.allowed_hosts:
            raise ValueError(
                f"Target hostname '{hostname}' is not in allowed_hosts: {self.allowed_hosts}"
            )

        # Enforce HTTPS for non-local targets; allow HTTP only for loopback.
        if parsed.scheme != "https" and not is_local_hostname(hostname):
            raise ValueError(
                f"HTTPS required for non-local host '{hostname}'. Got scheme: {parsed.scheme}"
            )

        return self

    @property
    def target_hostname(self) -> str:
        """Lower-cased hostname of the target URL."""
        return hostname_of(self.target_url)

    def is_local_target(self) -> bool:
        """True when the target is a loopback/localhost development target."""
        return is_local_hostname(self.target_hostname)


def load_config(config_path: str | Path) -> AppConfig:
    """Load configuration from a JSON file.

    Args:
        config_path: Path to the JSON configuration file.

    Returns:
        Validated AppConfig instance.

    Raises:
        ConfigError: If configuration is invalid or file not found.
    """
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON in configuration file: {e}")

    # Allow environment variable overrides for sensitive values
    if "username" in data.get("auth", {}) and not data["auth"]["username"]:
        data["auth"]["username"] = os.environ.get("AUTH_TEST_USERNAME", "")

    try:
        return AppConfig(**data)
    except Exception as e:
        raise ConfigError(f"Configuration validation failed: {e}")


def load_raw_config(config_path: str | Path) -> Dict[str, Any]:
    """Load the raw configuration dict (unvalidated) for editing.

    Secret-looking keys are dropped so the editor never round-trips a password
    that may have been (incorrectly) left in a config file.
    """
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON in configuration file: {e}")
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a JSON object")
    _strip_secrets_in_place(data)
    return data


# Dotted config paths that hold secrets and must never be written to JSON.
SECRET_CONFIG_PATHS = {
    "auth.password",
    "auth.access_token",
    "auth.client_secret",
}


def _strip_secrets_in_place(data: Dict[str, Any]) -> None:
    """Remove secret values from a config dict (in place), recursively."""
    for secret_path in SECRET_CONFIG_PATHS:
        if "." in secret_path:
            section, key = secret_path.split(".", 1)
            if isinstance(data.get(section), dict):
                data[section].pop(key, None)
    # Drop any obviously-secret keys anywhere in the tree.
    for value in data.values():
        if isinstance(value, dict):
            _strip_secrets_in_place(value)


def backup_config(config_path: str | Path) -> Optional[Path]:
    """Create a timestamped backup of an existing configuration file.

    Returns the backup path, or None if the source does not exist.
    """
    path = Path(config_path)
    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = path.with_suffix(path.suffix + f".{stamp}.bak")
    shutil.copy2(path, backup_path)
    return backup_path


def write_config_atomic(config_path: str | Path, data: Dict[str, Any]) -> None:
    """Write configuration atomically (write-to-temp then os.replace).

    Secrets are stripped before writing so an interrupted or careless write
    can never persist a password/token into the JSON config.
    """
    path = Path(config_path)
    safe = dict(data)
    _strip_secrets_in_place(safe)

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)
        except OSError:
            pass
        raise


def create_example_config(output_path: str | Path) -> None:
    """Create an example configuration file."""
    example = {
        "target_url": "https://your-authorized-app.example.com/login",
        "allowed_hosts": [
            "your-authorized-app.example.com",
            "localhost"
        ],
        "auth": {
            "provider": "custom",
            "username": "YOUR_DEDICATED_TEST_USERNAME",
            "username_selector": "input[name=\"email\"]",
            "password_selector": "input[name=\"password\"]",
            "submit_selector": "button[type=\"submit\"]",
            "success_url_patterns": [
                "/dashboard"
            ],
            "success_selectors": [
                "[data-testid=\"user-menu\"]"
            ],
            "failure_selectors": [
                "[data-testid=\"login-error\"]",
                ".error-message"
            ],
            "success_on_navigation_without_failure": False
        },
        "browser": {
            "browser": "chromium",
            "headless": False,
            "navigation_timeout_ms": 15000,
            "delay_before_submit_seconds": 1,
            "inter_entry_delay_seconds": 0,
            "viewport_width": 1280,
            "viewport_height": 720
        },
        "report": {
            "report_directory": "reports",
            "timestamp_format": "%Y-%m-%dT%H:%M:%S%z",
            "log_level": "INFO",
            "retention_days": 0,
            "diagnostic_verbosity": "normal"
        },
        "security": {
            "http_status_codes": [403, 429],
            "blocking_text_patterns": [
                "too many attempts",
                "too many requests",
                "rate limit",
                "captcha",
                "temporarily blocked",
                "try again later",
                "account locked",
                "access denied",
                "blocked",
                "suspicious activity",
                "verify you are human"
            ],
            "captcha_selectors": [
                "[data-testid*='captcha']",
                "[id*='captcha']",
                "[class*='captcha']",
                "iframe[src*='recaptcha']",
                "iframe[src*='hcaptcha']",
                ".g-recaptcha",
                "#h-captcha"
            ],
            "mfa_selectors": [
                "[data-testid*='mfa']",
                "[data-testid*='2fa']",
                "[id*='mfa']",
                "[id*='2fa']",
                ".mfa-challenge",
                ".two-factor"
            ]
        },
        "stop_on_security_challenge": True,
        "always_on_top": False,
        "password_file": "password.txt",
        "include_password_in_report": False
    }

    with Path(output_path).open("w", encoding="utf-8") as f:
        json.dump(example, f, indent=2, ensure_ascii=False)
