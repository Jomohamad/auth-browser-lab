"""Configuration management for the authentication testing tool.

This module handles loading, validating, and providing access to the
application configuration. It supports loading from JSON configuration
files and environment variables.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class ConfigError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


class AuthenticationProvider(str):
    """Supported authentication providers."""
    CUSTOM = "custom"
    AUTHJS = "authjs"
    NEXT_AUTH = "nextauth"
    CLERK = "clerk"
    SUPABASE = "supabase"


class ExecutionMode(str):
    """Execution modes for the tool."""
    PRODUCTION = "production"
    STAGING = "staging"


class ResultCategory(str):
    """Result classification categories."""
    SUCCESS_CONFIRMED = "SUCCESS_CONFIRMED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    STOPPED_SECURITY_CHALLENGE = "STOPPED_SECURITY_CHALLENGE"
    STOPPED_RATE_LIMIT = "STOPPED_RATE_LIMIT"
    STOPPED_ACCESS_DENIED = "STOPPED_ACCESS_DENIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    NAVIGATION_ERROR = "NAVIGATION_ERROR"


class BrowserType(str):
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
    """Authentication-specific configuration."""
    provider: AuthenticationProvider = Field(
        default=AuthenticationProvider.CUSTOM,
        description="Authentication provider type"
    )
    username: str = Field(
        default="",
        description="Test account username/email"
    )
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


class ReportConfig(BaseModel):
    """Reporting configuration."""
    report_directory: str = Field(
        default="reports",
        description="Directory for CSV reports"
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
    execution_mode: ExecutionMode = Field(
        default=ExecutionMode.PRODUCTION,
        description="Execution mode: production or staging"
    )
    maximum_attempts: int = Field(
        default=1,
        description="Maximum authentication attempts (staging mode only)"
    )
    password_file: str = Field(
        default="password.txt",
        description="Path to password file"
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

    @field_validator("execution_mode")
    @classmethod
    def validate_execution_mode(cls, v: ExecutionMode) -> ExecutionMode:
        """Validate execution mode."""
        if v not in (ExecutionMode.PRODUCTION, ExecutionMode.STAGING):
            raise ValueError(f"execution_mode must be 'production' or 'staging', got '{v}'")
        return v

    @field_validator("maximum_attempts")
    @classmethod
    def validate_maximum_attempts(cls, v: int) -> int:
        """Validate maximum attempts."""
        if v < 1:
            raise ValueError("maximum_attempts must be at least 1")
        if v > 10:
            raise ValueError("maximum_attempts cannot exceed 10")
        return v

    @model_validator(mode="after")
    def validate_hostname_match(self) -> "AppConfig":
        """Validate that target URL hostname is in allowed_hosts."""
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        
        if hostname not in self.allowed_hosts:
            raise ValueError(
                f"Target hostname '{hostname}' is not in allowed_hosts: {self.allowed_hosts}"
            )
        
        # Enforce HTTPS unless localhost
        if parsed.scheme != "https" and hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(
                f"HTTPS required for non-localhost hosts. Got scheme: {parsed.scheme}"
            )
        
        return self


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


def create_example_config(output_path: str | Path) -> None:
    """Create an example configuration file.
    
    Args:
        output_path: Path where the example config should be written.
    """
    example = {
        "target_url": "https://your-app.example.com/login",
        "allowed_hosts": [
            "your-app.example.com",
            "localhost"
        ],
        "auth": {
            "provider": "custom",
            "username": "test-account@example.com",
            "username_selector": "input[name=\"email\"]",
            "password_selector": "input[name=\"password\"]",
            "submit_selector": "button[type=\"submit\"]",
            "success_url_patterns": [
                "/dashboard",
                "/home",
                "/app"
            ],
            "success_selectors": [
                "[data-testid=\"user-menu\"]",
                ".user-profile",
                "a[href*=\"logout\"]"
            ],
            "failure_selectors": [
                "[data-testid=\"error-message\"]",
                ".auth-error",
                ".alert-danger"
            ]
        },
        "browser": {
            "browser": "chromium",
            "headless": false,
            "navigation_timeout_ms": 15000,
            "delay_before_submit_seconds": 3
        },
        "report": {
            "report_directory": "reports"
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
        "execution_mode": "production",
        "maximum_attempts": 1,
        "password_file": "password.txt"
    }
    
    with Path(output_path).open("w", encoding="utf-8") as f:
        json.dump(example, f, indent=2)