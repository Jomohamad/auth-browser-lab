"""Unit tests for configuration validation, allowlist, and HTTPS enforcement."""

import json
import pytest
from pathlib import Path

from auth_audit.config import (
    load_config,
    create_example_config,
    AppConfig,
    ConfigError,
    AuthenticationProvider,
    BrowserType,
)


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_valid_minimal_config(self, tmp_path):
        """A minimal HTTPS config with an allowlisted host loads."""
        config_data = {
            "target_url": "https://app.example.com/login",
            "allowed_hosts": ["app.example.com"],
        }
        f = tmp_path / "config.json"
        f.write_text(json.dumps(config_data))

        config = load_config(f)

        assert config.target_url == "https://app.example.com/login"
        assert config.allowed_hosts == ["app.example.com"]
        assert config.auth.provider == AuthenticationProvider.CUSTOM
        assert config.password_file == "password.txt"

    def test_valid_full_config(self, tmp_path):
        """A complete HTTPS config loads with all overrides applied."""
        config_data = {
            "target_url": "https://app.example.com/login",
            "allowed_hosts": ["app.example.com", "localhost"],
            "auth": {
                "provider": "authjs",
                "username": "localtest",
                "username_selector": "input#email",
                "password_selector": "input#password",
                "submit_selector": "button[type=submit]",
                "success_url_patterns": ["/dashboard"],
                "success_selectors": [".user-menu"],
                "failure_selectors": [".error-message"],
            },
            "browser": {
                "browser": "firefox",
                "headless": True,
                "navigation_timeout_ms": 30000,
                "delay_before_submit_seconds": 0.5,
            },
            "report": {"report_directory": "custom-reports"},
            "security": {
                "http_status_codes": [403, 429, 503],
                "blocking_text_patterns": ["rate limit", "blocked"],
                "captcha_selectors": [".captcha"],
                "mfa_selectors": [".mfa"],
            },
            "stop_on_security_challenge": False,
            "password_file": "custom-passwords.txt",
        }
        f = tmp_path / "config.json"
        f.write_text(json.dumps(config_data))

        config = load_config(f)

        assert config.auth.provider == AuthenticationProvider.AUTHJS
        assert config.browser.browser == BrowserType.FIREFOX
        assert config.browser.headless is True
        assert config.stop_on_security_challenge is False

    def test_invalid_target_url_missing_scheme(self, tmp_path):
        cfg = {"target_url": "app.example.com/login", "allowed_hosts": ["app.example.com"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        with pytest.raises(ConfigError) as exc:
            load_config(f)
        assert "valid URL" in str(exc.value)

    def test_invalid_target_url_missing_host(self, tmp_path):
        cfg = {"target_url": "https:///login", "allowed_hosts": ["app.example.com"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        with pytest.raises(ConfigError) as exc:
            load_config(f)
        assert "valid URL" in str(exc.value)

    def test_hostname_not_in_allowed_hosts(self, tmp_path):
        """Target host must be present in allowed_hosts."""
        cfg = {"target_url": "https://evil.example/login", "allowed_hosts": ["app.example.com"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        with pytest.raises(ConfigError) as exc:
            load_config(f)
        assert "not in allowed_hosts" in str(exc.value)

    def test_allowlisted_remote_host_accepted(self, tmp_path):
        """An HTTPS remote host present in the allowlist is accepted."""
        cfg = {
            "target_url": "https://dulms.deltauniv.edu.eg/login.aspx",
            "allowed_hosts": ["dulms.deltauniv.edu.eg"],
        }
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        config = load_config(f)
        assert config.target_url == "https://dulms.deltauniv.edu.eg/login.aspx"

    def test_empty_allowed_hosts_rejected(self, tmp_path):
        cfg = {"target_url": "https://app.example.com/login", "allowed_hosts": []}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        with pytest.raises(ConfigError) as exc:
            load_config(f)
        assert "at least one host" in str(exc.value)

    def test_http_rejected_for_non_local_host(self, tmp_path):
        """HTTP is rejected for non-local hosts."""
        cfg = {"target_url": "http://app.example.com/login", "allowed_hosts": ["app.example.com"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        with pytest.raises(ConfigError) as exc:
            load_config(f)
        assert "HTTPS required" in str(exc.value)

    def test_http_allowed_for_localhost(self, tmp_path):
        """HTTP is allowed only for loopback development targets."""
        cfg = {"target_url": "http://localhost:3000/login", "allowed_hosts": ["localhost"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        config = load_config(f)
        assert config.target_url == "http://localhost:3000/login"

    def test_http_allowed_for_loopback_ip(self, tmp_path):
        cfg = {"target_url": "http://127.0.0.1:8000/login", "allowed_hosts": ["127.0.0.1"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        config = load_config(f)
        assert config.target_url == "http://127.0.0.1:8000/login"

    def test_create_example_config(self, tmp_path):
        out = tmp_path / "example.json"
        create_example_config(out)
        data = json.loads(out.read_text())
        for key in ("target_url", "allowed_hosts", "auth", "browser", "security"):
            assert key in data


class TestNoAttemptLimitConfig:
    """Verify the obsolete attempt-limit setting is gone from config."""

    def test_appconfig_has_no_attempt_limit_fields(self):
        fields = set(AppConfig.model_fields.keys())
        assert "maximum_attempts" not in fields
        assert "max_attempts" not in fields
        assert "execution_mode" not in fields

    def test_example_config_has_no_attempt_keys(self, tmp_path):
        out = tmp_path / "example.json"
        create_example_config(out)
        data = json.loads(out.read_text())
        assert "maximum_attempts" not in data
        assert "max_attempts" not in data
        assert "execution_mode" not in data


class TestConfigModels:
    """Tests for configuration model default values."""

    def test_auth_config_defaults(self):
        from auth_audit.config import AuthConfig

        auth = AuthConfig()
        assert auth.provider == AuthenticationProvider.CUSTOM
        assert auth.username == ""

    def test_browser_config_defaults(self):
        from auth_audit.config import BrowserConfig

        browser = BrowserConfig()
        assert browser.browser == BrowserType.CHROMIUM
        assert browser.headless is False
        assert browser.navigation_timeout_ms == 15000
        assert browser.delay_before_submit_seconds == 3.0

    def test_security_config_defaults(self):
        from auth_audit.config import SecurityChallengeConfig

        security = SecurityChallengeConfig()
        assert 403 in security.http_status_codes
        assert 429 in security.http_status_codes
        assert "captcha" in security.blocking_text_patterns
        assert "rate limit" in security.blocking_text_patterns
