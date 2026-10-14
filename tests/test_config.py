"""Unit tests for configuration validation."""

import json
import pytest
from pathlib import Path

from src.config import (
    load_config,
    create_example_config,
    AppConfig,
    ConfigError,
    ExecutionMode,
    AuthenticationProvider,
    BrowserType,
)


class TestConfigValidation:
    """Tests for configuration validation."""
    
    def test_valid_minimal_config(self, tmp_path):
        """Test loading a valid minimal configuration."""
        config_data = {
            "target_url": "https://example.com/login",
            "allowed_hosts": ["example.com"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        config = load_config(config_file)
        
        assert config.target_url == "https://example.com/login"
        assert config.allowed_hosts == ["example.com"]
        assert config.auth.provider == AuthenticationProvider.CUSTOM
        assert config.execution_mode == ExecutionMode.PRODUCTION
        assert config.maximum_attempts == 1
    
    def test_valid_full_config(self, tmp_path):
        """Test loading a complete configuration."""
        config_data = {
            "target_url": "https://app.example.com/login",
            "allowed_hosts": ["app.example.com", "localhost"],
            "auth": {
                "provider": "authjs",
                "username": "test@example.com",
                "username_selector": "input#email",
                "password_selector": "input#password",
                "submit_selector": "button[type=submit]",
                "success_url_patterns": ["/dashboard"],
                "success_selectors": [".user-menu"],
                "failure_selectors": [".error-message"]
            },
            "browser": {
                "browser": "firefox",
                "headless": True,
                "navigation_timeout_ms": 30000,
                "delay_before_submit_seconds": 5
            },
            "report": {
                "report_directory": "custom-reports"
            },
            "security": {
                "http_status_codes": [403, 429, 503],
                "blocking_text_patterns": ["rate limit", "blocked"],
                "captcha_selectors": [".captcha"],
                "mfa_selectors": [".mfa"]
            },
            "stop_on_security_challenge": False,
            "execution_mode": "staging",
            "maximum_attempts": 3,
            "password_file": "custom-passwords.txt"
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        config = load_config(config_file)
        
        assert config.auth.provider == AuthenticationProvider.AUTHJS
        assert config.browser.browser == BrowserType.FIREFOX
        assert config.browser.headless is True
        assert config.execution_mode == ExecutionMode.STAGING
        assert config.maximum_attempts == 3
        assert config.stop_on_security_challenge is False
    
    def test_invalid_target_url_missing_scheme(self, tmp_path):
        """Test that URL without scheme is rejected."""
        config_data = {
            "target_url": "example.com/login",
            "allowed_hosts": ["example.com"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "valid URL" in str(exc.value)
    
    def test_invalid_target_url_missing_host(self, tmp_path):
        """Test that URL without host is rejected."""
        config_data = {
            "target_url": "https:///login",
            "allowed_hosts": ["example.com"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "valid URL" in str(exc.value)
    
    def test_hostname_not_in_allowed_hosts(self, tmp_path):
        """Test that target hostname must be in allowed_hosts."""
        config_data = {
            "target_url": "https://evil.com/login",
            "allowed_hosts": ["example.com"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "not in allowed_hosts" in str(exc.value)
    
    def test_http_not_allowed_for_non_localhost(self, tmp_path):
        """Test that HTTP is rejected for non-localhost hosts."""
        config_data = {
            "target_url": "http://example.com/login",
            "allowed_hosts": ["example.com"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "HTTPS required" in str(exc.value)
    
    def test_http_allowed_for_localhost(self, tmp_path):
        """Test that HTTP is allowed for localhost."""
        config_data = {
            "target_url": "http://localhost:3000/login",
            "allowed_hosts": ["localhost"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        config = load_config(config_file)
        assert config.target_url == "http://localhost:3000/login"
    
    def test_empty_allowed_hosts_rejected(self, tmp_path):
        """Test that empty allowed_hosts is rejected."""
        config_data = {
            "target_url": "https://example.com/login",
            "allowed_hosts": [],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "at least one host" in str(exc.value)
    
    def test_invalid_execution_mode(self, tmp_path):
        """Test that invalid execution mode is rejected."""
        config_data = {
            "target_url": "https://example.com/login",
            "allowed_hosts": ["example.com"],
            "execution_mode": "invalid",
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "execution_mode must be" in str(exc.value)
    
    def test_maximum_attempts_too_high(self, tmp_path):
        """Test that maximum_attempts > 10 is rejected."""
        config_data = {
            "target_url": "https://example.com/login",
            "allowed_hosts": ["example.com"],
            "execution_mode": "staging",
            "maximum_attempts": 15,
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "cannot exceed 10" in str(exc.value)
    
    def test_maximum_attempts_zero_rejected(self, tmp_path):
        """Test that maximum_attempts < 1 is rejected."""
        config_data = {
            "target_url": "https://example.com/login",
            "allowed_hosts": ["example.com"],
            "execution_mode": "staging",
            "maximum_attempts": 0,
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "at least 1" in str(exc.value)
    
    def test_create_example_config(self, tmp_path):
        """Test creating example configuration file."""
        output_path = tmp_path / "example.json"
        create_example_config(output_path)
        
        assert output_path.exists()
        
        with output_path.open() as f:
            data = json.load(f)
        
        assert "target_url" in data
        assert "allowed_hosts" in data
        assert "auth" in data
        assert "browser" in data
        assert "security" in data


class TestConfigModels:
    """Tests for configuration model validation."""
    
    def test_auth_config_defaults(self):
        """Test AuthConfig default values."""
        from src.config import AuthConfig
        
        auth = AuthConfig()
        
        assert auth.provider == AuthenticationProvider.CUSTOM
        assert auth.username == ""
        assert auth.username_selector == 'input[name="email"]'
        assert auth.password_selector == 'input[name="password"]'
        assert auth.submit_selector == 'button[type="submit"]'
    
    def test_browser_config_defaults(self):
        """Test BrowserConfig default values."""
        from src.config import BrowserConfig
        
        browser = BrowserConfig()
        
        assert browser.browser == BrowserType.CHROMIUM
        assert browser.headless is False
        assert browser.navigation_timeout_ms == 15000
        assert browser.delay_before_submit_seconds == 3.0
    
    def test_security_config_defaults(self):
        """Test SecurityChallengeConfig default values."""
        from src.config import SecurityChallengeConfig
        
        security = SecurityChallengeConfig()
        
        assert 403 in security.http_status_codes
        assert 429 in security.http_status_codes
        assert "captcha" in security.blocking_text_patterns
        assert "rate limit" in security.blocking_text_patterns