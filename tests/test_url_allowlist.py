# Signed by JOE
"""Unit tests for allowlist enforcement, redirect/origin blocking, HTTPS, and
CSV sanitization."""

import pytest
from unittest.mock import Mock
from playwright.sync_api import Page, Response

from auth_audit.config import (
    AuthConfig,
    SecurityChallengeConfig,
    AppConfig,
    BrowserConfig,
    ReportConfig,
)
from auth_audit.browser_automation import AuthTester
from auth_audit.result_classifier import AuthenticationResult


def make_remote_config(
    target="https://app.example.com/login",
    allowed_hosts=("app.example.com",),
) -> AppConfig:
    """Build an HTTPS AppConfig with an explicit allowlist."""
    return AppConfig(
        target_url=target,
        allowed_hosts=list(allowed_hosts),
        auth=AuthConfig(
            provider="custom",
            username="testuser",
            username_selector="#username",
            password_selector="#password",
            submit_selector="#login-btn",
            success_url_patterns=["/__never_match__"],
            success_selectors=["#__never_present__"],
            failure_selectors=["#__never_failure__"],
        ),
        browser=BrowserConfig(
            browser="chromium",
            headless=True,
            navigation_timeout_ms=15000,
            delay_before_submit_seconds=0,
        ),
        report=ReportConfig(report_directory="reports"),
        security=SecurityChallengeConfig(),
        stop_on_security_challenge=True,
        password_file="password.txt",
    )


class TestHostAllowlistHelper:
    """Tests for the AuthTester host allowlist helper."""

    @pytest.fixture
    def tester(self):
        return AuthTester(make_remote_config())

    def test_allowed_hosts_return_true(self, tester):
        assert tester._check_host_allowed("https://app.example.com/login") is True
        assert tester._check_host_allowed("https://app.example.com/dashboard") is True

    def test_unauthorized_hosts_return_false(self, tester):
        assert tester._check_host_allowed("https://evil.example/phishing") is False
        assert tester._check_host_allowed("https://other.example/login") is False
        assert tester._check_host_allowed("http://127.0.0.1:5000/login") is False

    def test_case_insensitive(self):
        tester = AuthTester(make_remote_config(allowed_hosts=("app.example.com",)))
        assert tester._check_host_allowed("https://APP.EXAMPLE.COM/x") is True

    def test_invalid_url(self, tester):
        assert tester._check_host_allowed("not-a-url") is False
        assert tester._check_host_allowed("") is False


def _build_mock_page(url: str, status: int = 200):
    page = Mock(spec=Page)
    page.url = url

    mock_locator = Mock()
    mock_locator.count.return_value = 1
    mock_locator.is_visible.return_value = True
    mock_locator.wait_for = Mock()
    mock_locator.fill = Mock()
    mock_locator.click = Mock()
    mock_locator.first = mock_locator
    mock_locator.inner_text.return_value = "page text"
    page.locator = Mock(return_value=mock_locator)

    page.goto = Mock(return_value=Mock(status=status))
    page.wait_for_load_state = Mock()
    page.wait_for_timeout = Mock()
    page.title = Mock(return_value="Mock Page")
    page.frames = []
    page.on = Mock()  # framenavigated listener registration
    return page


class TestRedirectAndOrigin:
    """Redirect to a host outside the allowlist must block before submitting."""

    def test_non_allowlisted_origin_blocks_submit(self):
        tester = AuthTester(make_remote_config())
        page = _build_mock_page("https://evil.example/phishing", status=200)
        tester.detector.check_page_content = Mock(return_value=None)
        tester.detector.check_navigation = Mock(return_value=None)

        result = tester._run_single_test(page, "somepassword", 1, 1)

        assert result.classification.result == AuthenticationResult.UNAUTHORIZED_HOST_BLOCKED
        # Credentials were never submitted.
        page.locator.return_value.click.assert_not_called()

    def test_allowlisted_origin_submits(self):
        tester = AuthTester(make_remote_config())
        page = _build_mock_page("https://app.example.com/login", status=200)
        tester.detector.check_page_content = Mock(return_value=None)
        tester.detector.check_navigation = Mock(return_value=None)

        result = tester._run_single_test(page, "somepassword", 1, 1)

        page.locator.return_value.click.assert_called_once()
        assert result.classification.result != AuthenticationResult.UNAUTHORIZED_HOST_BLOCKED
        assert result.navigation_error is False


class TestCSVReportSanitization:
    """CSV sanitization must not leak credentials or URL query strings."""

    @pytest.fixture
    def reporter(self, tmp_path):
        from auth_audit.reporter import CSVReporter
        return CSVReporter(str(tmp_path / "reports"))

    def test_sanitize_password_in_summary(self, reporter):
        sanitized = reporter._sanitize_summary(
            "User tried password MySecretPass123 and failed",
            secrets=["MySecretPass123"],
        )
        assert "MySecretPass123" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitize_token_in_summary(self, reporter):
        s = reporter._sanitize_summary("Token: abcdefghijklmnopqrstuvwxyz123456")
        assert "abcdefghijklmnopqrstuvwxyz123456" not in s

    def test_sanitize_jwt_in_summary(self, reporter):
        s = reporter._sanitize_summary("JWT: eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0.NTk2fQ.abc")
        assert "eyJ" not in s or "[REDACTED]" in s

    def test_sanitize_cookie_in_summary(self, reporter):
        s = reporter._sanitize_summary("session=abc123; token=xyz789")
        assert "session=[REDACTED]" in s
        assert "token=[REDACTED]" in s

    def test_create_record_strips_query_and_fragment(self, reporter):
        from auth_audit.result_classifier import AuthenticationResult
        record = reporter.create_record(
            target_url="https://app.example.com/login?tab=a#frag",
            auth_provider="custom",
            attempt_number=1,
            total_entries=2,
            result=AuthenticationResult.SUCCESS_CONFIRMED,
            http_status=200,
            login_page_status=200,
            auth_response_status=200,
            security_challenge_detected=False,
            elapsed_time_ms=5,
            final_page_url="https://app.example.com/dashboard?token=SECRET&sid=1#x",
            page_title="Dashboard",
            form_detected=True,
            selector_diagnostic="",
            diagnostic_summary="ok",
            secrets=["SECRET"],
        )
        assert "?" not in record.final_page_path
        assert "#" not in record.final_page_path
        assert "SECRET" not in record.final_page_path
        assert record.total_entries == 2

    def test_report_has_total_entries_column(self, reporter):
        from auth_audit.reporter import TestReportRecord
        path = reporter.write_record(
            TestReportRecord(
                timestamp_utc="2026-01-01T00:00:00+00:00",
                target_host="app.example.com",
                authentication_provider="custom",
                attempt_number=1,
                total_entries=1,
                result="AUTHENTICATION_FAILED",
                http_status=200,
                login_page_status=200,
                auth_response_status=200,
                security_challenge_detected=False,
                elapsed_time_ms=10,
                final_page_path="https://app.example.com/login",
                page_title="Login",
                form_detected=True,
                selector_diagnostic="",
                diagnostic_summary="",
            )
        )
        header = path.read_text(encoding="utf-8").splitlines()[0]
        assert "total_entries" in header
        assert "attempt_number" in header
        assert "execution_mode" not in header
        assert "maximum_attempts" not in header


class TestHTTPSEnforcement:
    """HTTPS is required for non-local hosts; HTTP allowed for loopback only."""

    def test_http_rejected_for_remote(self, tmp_path):
        from auth_audit.config import load_config, ConfigError
        import json

        cfg = {"target_url": "http://app.example.com/login", "allowed_hosts": ["app.example.com"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        with pytest.raises(ConfigError) as exc:
            load_config(f)
        assert "HTTPS required" in str(exc.value)

    def test_https_remote_accepted(self, tmp_path):
        from auth_audit.config import load_config
        import json

        cfg = {"target_url": "https://app.example.com/login", "allowed_hosts": ["app.example.com"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        config = load_config(f)
        assert config.target_url == "https://app.example.com/login"

    def test_http_allowed_for_localhost(self, tmp_path):
        from auth_audit.config import load_config
        import json

        cfg = {"target_url": "http://localhost:3000/login", "allowed_hosts": ["localhost"]}
        f = tmp_path / "config.json"
        f.write_text(json.dumps(cfg))
        config = load_config(f)
        assert config.target_url == "http://localhost:3000/login"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
