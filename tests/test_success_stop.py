# Signed by JOE
"""Regression tests: stop the loop on confirmed success, never infer success
from a 302, keep inconclusive as inconclusive, and never leak credentials.

These tests use mocks only. No live authentication is performed here.
"""

import threading
import time

import pytest
from unittest.mock import Mock
from playwright.sync_api import Page
from pydantic import ValidationError

from auth_audit.config import (
    AppConfig,
    AuthConfig,
    BrowserConfig,
    ReportConfig,
    SecurityChallengeConfig,
)
from auth_audit.auth_flow import AuthTester
from auth_audit.auth_flow import TestRunResult as RunResult
from auth_audit.password_handler import PasswordFileResult
from auth_audit.result_classifier import (
    ResultClassifier,
    ClassificationResult,
    AuthenticationResult,
)
from auth_audit.security import SecurityChallengeResult


def make_config(
    report_dir,
    success_on_nav=False,
    include_pw_in_report=False,
    concurrent_windows=1,
):
    return AppConfig(
        target_url="https://app.example.com/login",
        allowed_hosts=["app.example.com"],
        auth=AuthConfig(
            provider="custom",
            username="testuser",
            username_selector="#username",
            password_selector="#password",
            submit_selector="#login-btn",
            success_url_patterns=["/dashboard"],
            success_selectors=[".user-menu"],
            failure_selectors=["#error-message"],
            success_on_navigation_without_failure=success_on_nav,
        ),
        browser=BrowserConfig(
            browser="chromium",
            headless=True,
            navigation_timeout_ms=15000,
            delay_before_submit_seconds=0,
            concurrent_windows=concurrent_windows,
        ),
        report=ReportConfig(report_directory=str(report_dir)),
        security=SecurityChallengeConfig(),
        stop_on_security_challenge=True,
        include_password_in_report=include_pw_in_report,
        password_file="password.txt",
    )


def make_result(state, *, diagnostic_summary="summary", security_challenge=None):
    confidence = "high" if state in (
        AuthenticationResult.SUCCESS_CONFIRMED,
        AuthenticationResult.AUTHENTICATION_FAILED,
        AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
    ) else "low"
    return RunResult(
        password_index=0,
        classification=ClassificationResult(
            result=state,
            confidence=confidence,
            diagnostic_summary=diagnostic_summary,
        ),
        http_status=302,
        login_page_status=200,
        auth_response_status=302,
        security_challenge=security_challenge,
        elapsed_time_ms=1,
        final_page_url="https://app.example.com/login",
        page_title="Login",
        redirect_chain=[],
        form_detected=True,
        selector_diagnostic="",
    )


# ---------------------------------------------------------------------------
# Classification: a 302 / redirect is NOT success unless an indicator matches.
# ---------------------------------------------------------------------------

def make_classifier_config(success_on_nav=False):
    return AppConfig(
        target_url="https://app.example.com/login",
        allowed_hosts=["app.example.com"],
        auth=AuthConfig(
            provider="custom",
            username="testuser",
            username_selector="#username",
            password_selector="#password",
            submit_selector="#login-btn",
            success_url_patterns=["/dashboard"],
            success_selectors=[".user-menu"],
            failure_selectors=["#error-message"],
            success_on_navigation_without_failure=success_on_nav,
        ),
        report=ReportConfig(report_directory="reports"),
        security=SecurityChallengeConfig(),
        password_file="password.txt",
    )


@pytest.fixture
def classifier():
    return ResultClassifier(make_classifier_config().auth)


def _mock_page(url, matching_selectors=(), body_text=""):
    page = Mock(spec=Page)
    page.url = url

    def locator_side_effect(selector):
        loc = Mock()
        loc.count.return_value = 1 if selector in matching_selectors else 0
        loc.inner_text.return_value = body_text
        return loc

    page.locator.side_effect = locator_side_effect
    return page


def test_302_alone_is_not_success(classifier):
    """An HTTP 302 with no configured indicator must be INCONCLUSIVE."""
    page = _mock_page("https://app.example.com/redirect-target")
    result = classifier.classify(page, http_status=302, security_challenge=None)
    assert result.result == AuthenticationResult.INCONCLUSIVE
    assert result.result != AuthenticationResult.SUCCESS_CONFIRMED


def test_redirect_to_login_page_is_not_success(classifier):
    """A redirect that lands back on the login page is not success."""
    page = _mock_page("https://app.example.com/login")
    result = classifier.classify(page, http_status=302, security_challenge=None)
    assert result.result != AuthenticationResult.SUCCESS_CONFIRMED
    # No failure indicator either -> ambiguous -> INCONCLUSIVE.
    assert result.result == AuthenticationResult.INCONCLUSIVE


def test_redirect_with_authenticated_indicator_is_success_url(classifier):
    """A redirect to an authenticated URL path is SUCCESS_CONFIRMED."""
    page = _mock_page("https://app.example.com/dashboard")
    result = classifier.classify(page, http_status=302, security_challenge=None)
    assert result.result == AuthenticationResult.SUCCESS_CONFIRMED


def test_redirect_with_authenticated_selector_is_success(classifier):
    """A redirect to a page with an authenticated-only element is success."""
    page = _mock_page("https://app.example.com/app", matching_selectors=(".user-menu",))
    result = classifier.classify(page, http_status=302, security_challenge=None)
    assert result.result == AuthenticationResult.SUCCESS_CONFIRMED


def test_failure_indicator_is_not_success(classifier):
    """An invalid-credentials element/text must yield AUTHENTICATION_FAILED."""
    page = _mock_page(
        "https://app.example.com/login",
        matching_selectors=("#error-message",),
        body_text="Invalid username or password",
    )
    result = classifier.classify(page, http_status=200, security_challenge=None)
    assert result.result == AuthenticationResult.AUTHENTICATION_FAILED
    assert result.result != AuthenticationResult.SUCCESS_CONFIRMED


def test_inconclusive_is_not_converted_to_success(classifier):
    """Ambiguous page state stays INCONCLUSIVE (never becomes success)."""
    page = _mock_page("https://app.example.com/unknown", body_text="Loading state")
    result = classifier.classify(page, http_status=302, security_challenge=None)
    assert result.result == AuthenticationResult.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Loop control: stop immediately after SUCCESS_CONFIRMED.
# ---------------------------------------------------------------------------

def _install_fake_browser(tester):
    browser = Mock()
    context = Mock()
    page = Mock()
    browser.new_context.return_value = context
    context.new_page.return_value = page
    tester._launch_browser = Mock(return_value=browser)
    return browser, context, page


def test_concurrent_windows_wait_until_all_pages_are_ready(tmp_path, monkeypatch):
    from auth_audit import auth_flow

    ready_pages = []
    ready_lock = threading.Lock()

    class FakePlaywrightContext:
        def __enter__(self):
            return object()

        def __exit__(self, *_args):
            return False

    def launch_browser(_playwright):
        page = Mock()
        context = Mock()

        def create_page():
            with ready_lock:
                ready_pages.append(page)
            return page

        context.new_page.side_effect = create_page
        browser = Mock()
        browser.new_context.return_value = context
        return browser

    monkeypatch.setattr(auth_flow, "sync_playwright", FakePlaywrightContext)
    tester = AuthTester(make_config(tmp_path, concurrent_windows=2))
    tester._launch_browser = Mock(side_effect=launch_browser)
    started_at = time.monotonic()

    def run_attempt(_page, _password, _attempt_number, _total, _observed=None):
        with ready_lock:
            assert len(ready_pages) == 2
        assert time.monotonic() - started_at >= 0.08
        return make_result(AuthenticationResult.AUTHENTICATION_FAILED)

    tester._run_single_test = Mock(side_effect=run_attempt)
    results = tester.run(
        PasswordFileResult(
            passwords=["p1", "p2", "p3", "p4"],
            count=4,
            source_path="password.txt",
        ),
        startup_delay_seconds=0.1,
        ui_mode=True,
    )

    assert len(results) == 4
    assert tester._launch_browser.call_count == 2


def test_loop_stops_after_success(tmp_path, capsys):
    tester = AuthTester(make_config(tmp_path))
    _install_fake_browser(tester)

    calls = []

    def side_effect(page, password, attempt_number, total):
        calls.append(attempt_number)
        if attempt_number >= 3:
            raise AssertionError("Entry processed after confirmed success")
        if attempt_number == 2:
            return make_result(AuthenticationResult.SUCCESS_CONFIRMED)
        return make_result(AuthenticationResult.AUTHENTICATION_FAILED)

    tester._run_single_test = Mock(side_effect=side_effect)

    passwords = PasswordFileResult(
        passwords=["p1", "p2", "p3", "p4"], count=4, source_path="password.txt"
    )
    results = tester.run(passwords)

    # Only two entries were processed; entries 3 and 4 were never touched.
    assert calls == [1, 2]
    assert len(results) == 2
    assert results[-1].classification.result == AuthenticationResult.SUCCESS_CONFIRMED

    out = capsys.readouterr().out
    assert "AUTHENTICATION_SUCCESS" in out
    assert "NOT PROCESSED" in out
    assert "entry #2" in out


def test_inconclusive_does_not_stop_and_is_not_success(tmp_path):
    tester = AuthTester(make_config(tmp_path))
    _install_fake_browser(tester)

    calls = []

    def side_effect(page, password, attempt_number, total):
        calls.append(attempt_number)
        if attempt_number == 1:
            return make_result(AuthenticationResult.INCONCLUSIVE)
        return make_result(AuthenticationResult.AUTHENTICATION_FAILED)

    tester._run_single_test = Mock(side_effect=side_effect)

    passwords = PasswordFileResult(
        passwords=["p1", "p2"], count=2, source_path="password.txt"
    )
    results = tester.run(passwords)

    # Both processed (inconclusive did not stop the loop).
    assert calls == [1, 2]
    assert all(r.classification.result != AuthenticationResult.SUCCESS_CONFIRMED
               for r in results)


def test_security_challenge_stops_loop(tmp_path, capsys):
    tester = AuthTester(make_config(tmp_path))
    _install_fake_browser(tester)

    calls = []

    def side_effect(page, password, attempt_number, total):
        calls.append(attempt_number)
        if attempt_number >= 2:
            raise AssertionError("Entry processed after security challenge")
        challenge = SecurityChallengeResult(detected=True, challenge_type="CAPTCHA")
        return make_result(
            AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
            security_challenge=challenge,
        )

    tester._run_single_test = Mock(side_effect=side_effect)

    passwords = PasswordFileResult(
        passwords=["p1", "p2", "p3"], count=3, source_path="password.txt"
    )
    results = tester.run(passwords)

    assert calls == [1]
    assert results[0].classification.result == AuthenticationResult.STOPPED_SECURITY_CHALLENGE
    out = capsys.readouterr().out
    assert "SECURITY_CHALLENGE" in out


# ---------------------------------------------------------------------------
# Report sanitization: the actual candidate password never reaches the report.
# ---------------------------------------------------------------------------

def test_report_redacts_password(tmp_path):
    tester = AuthTester(make_config(tmp_path))
    secret = "SuperSecretTestPw123"
    passwords = PasswordFileResult(passwords=[secret], count=1, source_path="password.txt")
    result = make_result(
        AuthenticationResult.AUTHENTICATION_FAILED,
        diagnostic_summary=f"attempt used {secret} and was rejected",
    )
    tester._write_report(result, passwords, 1)

    report = tmp_path / f"auth-test-{result_today()}.csv"
    content = report.read_text(encoding="utf-8")
    assert secret not in content
    assert "[REDACTED]" in content


def test_report_includes_password_when_flag_enabled(tmp_path):
    """With include_password_in_report=True the candidate is in the report."""
    tester = AuthTester(make_config(tmp_path, include_pw_in_report=True))
    secret = "RealWorkingPw_42"
    passwords = PasswordFileResult(passwords=[secret], count=1, source_path="password.txt")
    result = make_result(
        AuthenticationResult.SUCCESS_CONFIRMED,
        diagnostic_summary=f"login succeeded with {secret}",
    )
    tester._write_report(result, passwords, 1)

    report = tmp_path / f"auth-test-{result_today()}.csv"
    content = report.read_text(encoding="utf-8")
    # Header exposes the dedicated column and the exact value is present.
    assert "candidate_password" in content.splitlines()[0]
    assert secret in content


def test_report_omits_password_when_flag_disabled(tmp_path):
    """Default (flag off) keeps the candidate out of the report."""
    tester = AuthTester(make_config(tmp_path, include_pw_in_report=False))
    secret = "ShouldNotAppear_99"
    passwords = PasswordFileResult(passwords=[secret], count=1, source_path="password.txt")
    result = make_result(
        AuthenticationResult.AUTHENTICATION_FAILED,
        diagnostic_summary=f"tried {secret} and failed",
    )
    tester._write_report(result, passwords, 1)

    report = tmp_path / f"auth-test-{result_today()}.csv"
    content = report.read_text(encoding="utf-8")
    assert secret not in content
    # Column still exists (schema stable) but the value is empty.
    assert "candidate_password" in content.splitlines()[0]


def result_today():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Allowlist: only configured/authorized hosts; off-allowlist blocks submit.
# ---------------------------------------------------------------------------

def test_config_rejects_host_not_in_allowlist(tmp_path):
    with pytest.raises(ValidationError):
        AppConfig(
            target_url="https://not-allowed.example/login",
            allowed_hosts=["app.example.com"],
            auth=AuthConfig(
                provider="custom", username="x",
                username_selector="#u", password_selector="#p", submit_selector="#b",
            ),
            browser=BrowserConfig(browser="chromium", headless=True),
            report=ReportConfig(report_directory=str(tmp_path)),
            security=SecurityChallengeConfig(),
            password_file="password.txt",
        )


def test_off_allowlist_redirect_blocks_submission(tmp_path):
    """A redirect to a host outside allowed_hosts blocks before submitting."""
    tester = AuthTester(make_config(tmp_path))

    page = Mock(spec=Page)
    page.url = "https://evil.example/phishing"
    loc = Mock()
    loc.count.return_value = 1
    loc.is_visible.return_value = True
    loc.first = loc
    loc.wait_for = Mock()
    loc.fill = Mock()
    loc.click = Mock()
    page.locator = Mock(return_value=loc)
    page.goto = Mock(return_value=Mock(status=200))
    page.wait_for_load_state = Mock()
    page.wait_for_timeout = Mock()
    page.title = Mock(return_value="Phish")
    page.frames = []
    page.on = Mock()

    tester.detector.check_page_content = Mock(return_value=None)

    result = tester._run_single_test(page, "pw", 1, 1)

    assert result.classification.result == AuthenticationResult.UNAUTHORIZED_HOST_BLOCKED
    loc.click.assert_not_called()


# ---------------------------------------------------------------------------
# Operator-defined success: navigate off login with no failure indicator.
# ---------------------------------------------------------------------------

def test_navigation_without_failure_is_success_when_enabled():
    classifier = ResultClassifier(make_classifier_config(success_on_nav=True).auth)
    page = _mock_page("https://app.example.com/profile/StudentProfile")
    result = classifier.classify(
        page, http_status=302, security_challenge=None, navigated_away=True
    )
    assert result.result == AuthenticationResult.SUCCESS_CONFIRMED


def test_navigation_flag_requires_navigation_away():
    """Even with the flag on, staying on the login page is NOT success."""
    classifier = ResultClassifier(make_classifier_config(success_on_nav=True).auth)
    page = _mock_page("https://app.example.com/login")
    result = classifier.classify(
        page, http_status=302, security_challenge=None, navigated_away=False
    )
    assert result.result != AuthenticationResult.SUCCESS_CONFIRMED
    assert result.result == AuthenticationResult.INCONCLUSIVE


def test_failure_indicator_overrides_navigation_success():
    """A failure element must win even if the page navigated (flag enabled)."""
    classifier = ResultClassifier(make_classifier_config(success_on_nav=True).auth)
    page = _mock_page(
        "https://app.example.com/login",
        matching_selectors=("#error-message",),
        body_text="Invalid username or password",
    )
    result = classifier.classify(
        page, http_status=302, security_challenge=None, navigated_away=True
    )
    assert result.result == AuthenticationResult.AUTHENTICATION_FAILED
    assert result.result != AuthenticationResult.SUCCESS_CONFIRMED


def test_flag_disabled_stays_inconclusive_without_indicator():
    classifier = ResultClassifier(make_classifier_config(success_on_nav=False).auth)
    page = _mock_page("https://app.example.com/profile/StudentProfile")
    result = classifier.classify(
        page, http_status=302, security_challenge=None, navigated_away=True
    )
    assert result.result == AuthenticationResult.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Terminal-only password print; never in the CSV report.
# ---------------------------------------------------------------------------

def test_success_prints_password_to_terminal_only(tmp_path, capsys):
    tester = AuthTester(make_config(tmp_path))
    _install_fake_browser(tester)

    secret = "RealWorkingPw_42"

    tester._run_single_test = Mock(
        return_value=make_result(AuthenticationResult.SUCCESS_CONFIRMED)
    )

    passwords = PasswordFileResult(
        passwords=["wrong1", secret], count=2, source_path="password.txt"
    )

    # Make it stop on the first entry (success) so the matched value is secret
    # only if the success happens on entry 2; force via side_effect.
    def side_effect(page, password, attempt_number, total):
        if attempt_number == 1:
            return make_result(AuthenticationResult.AUTHENTICATION_FAILED)
        return make_result(AuthenticationResult.SUCCESS_CONFIRMED)

    tester._run_single_test = Mock(side_effect=side_effect)

    results = tester.run(passwords)

    # Success occurred on entry 2.
    assert results[-1].classification.result == AuthenticationResult.SUCCESS_CONFIRMED

    out = capsys.readouterr().out
    # Password printed to terminal for the operator's own testing.
    assert "Matched password (terminal only): %s" % secret in out
    assert "AUTHENTICATION_SUCCESS" in out

    # But the CSV report must NOT contain the secret value.
    report = tmp_path / f"auth-test-{result_today()}.csv"
    content = report.read_text(encoding="utf-8")
    assert secret not in content


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
