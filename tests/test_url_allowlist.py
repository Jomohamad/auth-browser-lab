"""Unit tests for URL allowlist and redirect behavior."""

import pytest
from unittest.mock import Mock, MagicMock
from playwright.sync_api import Page, Response

from auth_audit.config import (
    AuthConfig, 
    SecurityChallengeConfig, 
    AppConfig,
    BrowserConfig,
    ReportConfig,
    ExecutionMode,
)
from auth_audit.browser_automation import AuthTester
from auth_audit.result_classifier import AuthenticationResult


class TestURLAllowlist:
    """Tests for URL allowlist enforcement and redirect behavior."""
    
    @pytest.fixture
    def app_config(self):
        """Create a test app configuration."""
        return AppConfig(
            target_url="https://example.com/login",
            allowed_hosts=["example.com", "auth.example.com"],
            auth=AuthConfig(
                provider="custom",
                username="test@example.com",
                username_selector='input[name="email"]',
                password_selector='input[name="password"]',
                submit_selector='button[type="submit"]',
            ),
            browser=BrowserConfig(
                browser="chromium",
                headless=True,
                navigation_timeout_ms=15000,
                delay_before_submit_seconds=0
            ),
            report=ReportConfig(report_directory="reports"),
            security=SecurityChallengeConfig(),
            stop_on_security_challenge=True,
            execution_mode=ExecutionMode.PRODUCTION,
            maximum_attempts=1,
            password_file="password.txt"
        )
    
    @pytest.fixture
    def mock_page(self):
        """Create a mock Playwright page."""
        page = Mock(spec=Page)
        page.url = "https://example.com/login"
        page.locator = Mock()
        return page
    
    def test_check_host_allowed_allowed_host(self, app_config):
        """Test that allowed hosts return True."""
        tester = AuthTester(app_config)
        
        assert tester._check_host_allowed("https://example.com/login") is True
        assert tester._check_host_allowed("https://example.com/dashboard") is True
        assert tester._check_host_allowed("https://auth.example.com/callback") is True
        assert tester._check_host_allowed("http://example.com/login") is True  # scheme doesn't matter
    
    def test_check_host_allowed_unauthorized_host(self, app_config):
        """Test that unauthorized hosts return False."""
        tester = AuthTester(app_config)
        
        assert tester._check_host_allowed("https://evil.com/login") is False
        assert tester._check_host_allowed("https://sub.example.com/login") is False  # subdomain not in list
        assert tester._check_host_allowed("https://example.org/login") is False
    
    def test_check_host_allowed_case_insensitive(self, app_config):
        """Test that hostname comparison is case insensitive."""
        tester = AuthTester(app_config)
        
        assert tester._check_host_allowed("https://EXAMPLE.COM/login") is True
        assert tester._check_host_allowed("https://Example.Com/login") is True
    
    def test_check_host_allowed_invalid_url(self, app_config):
        """Test that invalid URLs return False."""
        tester = AuthTester(app_config)
        
        assert tester._check_host_allowed("not-a-url") is False
        assert tester._check_host_allowed("") is False


class TestUnauthorizedRedirect:
    """Tests for detecting unauthorized redirects during authentication."""
    
    @pytest.fixture
    def app_config(self):
        """Create a test app configuration."""
        return AppConfig(
            target_url="https://example.com/login",
            allowed_hosts=["example.com"],
            auth=AuthConfig(
                provider="custom",
                username="test@example.com",
                username_selector='input[name="email"]',
                password_selector='input[name="password"]',
                submit_selector='button[type="submit"]',
            ),
            browser=BrowserConfig(
                browser="chromium",
                headless=True,
                navigation_timeout_ms=15000,
                delay_before_submit_seconds=0
            ),
            report=ReportConfig(report_directory="reports"),
            security=SecurityChallengeConfig(),
            stop_on_security_challenge=True,
            execution_mode=ExecutionMode.PRODUCTION,
            maximum_attempts=1,
            password_file="password.txt"
        )
    
    def test_navigation_to_unauthorized_host_returns_navigation_error(self, app_config):
        """Test that navigation to unauthorized host returns NAVIGATION_ERROR."""
        tester = AuthTester(app_config)
        
        # Create a mock page that navigates to unauthorized host
        page = Mock(spec=Page)
        page.url = "https://evil.com/phishing"
        page.locator = Mock()
        page.locator.return_value.wait_for = Mock()
        page.locator.return_value.fill = Mock()
        page.locator.return_value.click = Mock()
        page.wait_for_load_state = Mock()
        page.wait_for_timeout = Mock()
        
        # Mock the detector to return no challenges
        tester.detector.check_page_content = Mock(return_value=None)
        tester.detector.check_navigation = Mock(return_value=None)
        
        result = tester._run_single_test(page, "password123", 1)
        
        assert result.classification.result == AuthenticationResult.NAVIGATION_ERROR
        assert "unauthorized host" in result.classification.diagnostic_summary.lower()
        assert result.navigation_error is True
    
    def test_navigation_to_authorized_host_continues(self, app_config):
        """Test that navigation to authorized host continues normally."""
        tester = AuthTester(app_config)
        
        # Create a mock page that navigates to authorized host
        page = Mock(spec=Page)
        page.url = "https://example.com/dashboard"
        page.locator = Mock()
        page.locator.return_value.wait_for = Mock()
        page.locator.return_value.fill = Mock()
        page.locator.return_value.click = Mock()
        page.wait_for_load_state = Mock()
        page.wait_for_timeout = Mock()
        page.locator.return_value.count.return_value = 0
        page.locator.return_value.inner_text.return_value = "Dashboard"
        
        # Mock the detector to return no challenges
        tester.detector.check_page_content = Mock(return_value=None)
        tester.detector.check_navigation = Mock(return_value=None)
        
        result = tester._run_single_test(page, "password123", 1)
        
        # Should not be NAVIGATION_ERROR from host check
        # Will be INCONCLUSIVE since no success/failure indicators
        assert result.classification.result != AuthenticationResult.NAVIGATION_ERROR or "unauthorized" not in result.classification.diagnostic_summary.lower()


class TestCSVReportSanitization:
    """Tests for CSV report sanitization."""
    
    @pytest.fixture
    def reporter(self, tmp_path):
        """Create a CSV reporter with temp directory."""
        from auth_audit.reporter import CSVReporter
        return CSVReporter(str(tmp_path / "reports"))
    
    def test_sanitize_password_in_summary(self, reporter):
        """Test that passwords are redacted from summary."""
        summary = "User tried password MySecretPass123 and failed"
        sanitized = reporter._sanitize_summary(summary)
        
        assert "MySecretPass123" not in sanitized
        assert "[REDACTED]" in sanitized
    
    def test_sanitize_token_in_summary(self, reporter):
        """Test that long tokens are redacted."""
        summary = "Token: abcdefghijklmnopqrstuvwxyz123456"
        sanitized = reporter._sanitize_summary(summary)
        
        assert "abcdefghijklmnopqrstuvwxyz123456" not in sanitized
        assert "[REDACTED]" in sanitized
    
    def test_sanitize_jwt_in_summary(self, reporter):
        """Test that JWT-like strings are redacted."""
        summary = "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        sanitized = reporter._sanitize_summary(summary)
        
        assert "eyJ" not in sanitized or "[REDACTED]" in sanitized
    
    def test_sanitize_cookie_in_summary(self, reporter):
        """Test that cookie patterns are redacted."""
        summary = "session=abc123; token=xyz789; csrf=token123"
        sanitized = reporter._sanitize_summary(summary)
        
        assert "session=[REDACTED]" in sanitized
        assert "token=[REDACTED]" in sanitized
        assert "csrf=[REDACTED]" in sanitized
    
    def test_sanitize_length_limit(self, reporter):
        """Test that summary is truncated at 500 chars."""
        # Use a long string that won't be redacted by other patterns
        summary = "This is a test summary that is very long and contains no sensitive patterns " * 10
        sanitized = reporter._sanitize_summary(summary)
        
        assert len(sanitized) <= 500
        assert sanitized.endswith("...")


class TestHTTPSAndLocalhost:
    """Tests for HTTPS enforcement and localhost exception."""
    
    def test_https_required_for_non_localhost(self, tmp_path):
        """Test that HTTPS is required for non-localhost hosts."""
        from auth_audit.config import load_config, ConfigError
        import json
        
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
        from auth_audit.config import load_config
        import json
        
        config_data = {
            "target_url": "http://localhost:3000/login",
            "allowed_hosts": ["localhost"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        config = load_config(config_file)
        assert config.target_url == "http://localhost:3000/login"
    
    def test_http_allowed_for_127_0_0_1(self, tmp_path):
        """Test that HTTP is allowed for 127.0.0.1."""
        from auth_audit.config import load_config
        import json
        
        config_data = {
            "target_url": "http://127.0.0.1:8000/login",
            "allowed_hosts": ["127.0.0.1"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        config = load_config(config_file)
        assert config.target_url == "http://127.0.0.1:8000/login"
    
    def test_wildcard_allowed_hosts_rejected(self, tmp_path):
        """Test that wildcard allowed_hosts is rejected by hostname validation."""
        from auth_audit.config import load_config, ConfigError
        import json
        
        config_data = {
            "target_url": "https://example.com/login",
            "allowed_hosts": ["*"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        
        # The hostname validation correctly rejects wildcard because
        # 'example.com' is not literally in the list ['*']
        with pytest.raises(ConfigError) as exc:
            load_config(config_file)
        assert "not in allowed_hosts" in str(exc.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])