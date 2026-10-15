# Signed by JOE
"""Browser automation for authentication testing.

This module handles the Playwright browser automation workflow
for authorized authentication testing.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from playwright.sync_api import Browser, BrowserContext, Page, Response, sync_playwright

from . import browser as browser_helpers
from .config import AppConfig
from .password_handler import PasswordFileResult, read_password_file
from .reporting import CSVReporter, TestReportRecord
from .result_classifier import ResultClassifier, ClassificationResult, AuthenticationResult
from .security import SecurityChallengeDetector, SecurityChallengeResult


@dataclass
class TestRunResult:
    """Result of a single test run."""
    password_index: int
    classification: ClassificationResult
    http_status: Optional[int]
    login_page_status: Optional[int]
    auth_response_status: Optional[int]
    security_challenge: Optional[SecurityChallengeResult]
    elapsed_time_ms: int
    final_page_url: str
    page_title: str
    redirect_chain: List[str]
    form_detected: bool
    selector_diagnostic: str
    navigation_error: bool = False
    error_message: str = ""


class AuthTester:
    """Main authentication testing orchestrator."""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.classifier = ResultClassifier(config.auth)
        self.detector = SecurityChallengeDetector(config.security)
        self.reporter = CSVReporter(config.report.report_directory)
        
        # State tracking
        self._observed_http_status: Optional[int] = None
        self._login_page_status: Optional[int] = None
        self._auth_response_status: Optional[int] = None
        self._security_challenge_detected: Optional[SecurityChallengeResult] = None
        self._stop_requested: bool = False
        self._redirect_chain: List[str] = []
        self._page_title: str = ""
        self._form_detected: bool = False
        self._selector_diagnostic: str = ""
        
        # Pre-compute allowed hosts set for fast lookup
        self._allowed_hosts = set(config.allowed_hosts)
    
    def _check_host_allowed(self, url: str) -> bool:
        """Check if the URL's hostname is in the allowed hosts list.
        
        Args:
            url: URL to check.
            
        Returns:
            True if host is allowed, False otherwise.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            return hostname in self._allowed_hosts
        except Exception:
            return False

    def _navigated_off_login(self, current_url: str) -> bool:
        """Return True if the final URL path differs from the login page path."""
        try:
            login_path = urlparse(self.config.target_url).path
            current_path = urlparse(current_url).path
            return current_path != login_path
        except Exception:
            return False
    
    def run(self, passwords: PasswordFileResult) -> List[TestRunResult]:
        """Run authentication tests for every entry in the password file.

        Each non-empty entry is processed exactly once, in file order. The
        loop stops **immediately** when a result is either:

        - ``SUCCESS_CONFIRMED`` (a configured success indicator was observed),
          or
        - a detected security challenge (when ``stop_on_security_challenge``).

        Ordinary ``AUTHENTICATION_FAILED`` and ``INCONCLUSIVE`` results do NOT
        stop the run. ``INCONCLUSIVE`` is never treated as success.

        Args:
            passwords: Validated password file result.

        Returns:
            List of test run results (one per processed entry).
        """
        results = []
        total = passwords.count

        print(
            f"\nLoaded {total} password entr{'y' if total == 1 else 'ies'} "
            f"from {passwords.source_path}. Processing sequentially."
        )

        with sync_playwright() as p:
            browser = self._launch_browser(p)
            context = None
            page = None
            try:
                context = browser.new_context(
                    **browser_helpers.build_context_options(
                        self.config.browser.viewport_width,
                        self.config.browser.viewport_height,
                    )
                )

                # Observe auth-related responses (status / challenge signals).
                context.on("response", lambda response: self._on_response(response))

                # Reuse ONE page/tab (same window) for every attempt.
                page = context.new_page()

                def handle_navigation(navigation):
                    self._redirect_chain.append(navigation.url)

                page.on("framenavigated", handle_navigation)

                pacing = self.config.browser.inter_entry_delay_seconds
                for i, password in enumerate(passwords.passwords):
                    if self._stop_requested:
                        print(
                            f"\n[STOP] Safety stop in effect. "
                            f"Skipping remaining {total - i} entr"
                            f"{'y' if total - i == 1 else 'ies'}."
                        )
                        break

                    # Optional pacing between entries (local mock list testing).
                    if i > 0 and pacing > 0:
                        time.sleep(pacing)

                    attempt_number = i + 1
                    print(f"\n--- Entry {attempt_number}/{total} ---")
                    print(f"Trying candidate password: {password}")

                    result = self._run_single_test(
                        page, password, attempt_number, total
                    )
                    results.append(result)

                    # Consolidated report for the whole run.
                    self._write_report(result, passwords, attempt_number)

                    state = result.classification.result

                    # Stop immediately on a positively confirmed success.
                    if state == AuthenticationResult.SUCCESS_CONFIRMED:
                        self._stop_requested = True
                        self._print_stop_block(
                            state.value,
                            attempt_number,
                            total - attempt_number,
                            "AUTHENTICATION_SUCCESS",
                            matched_value=password,
                        )
                        break

                    # Stop on a detected security challenge.
                    if (
                        self.config.stop_on_security_challenge
                        and result.security_challenge
                        and result.security_challenge.detected
                    ):
                        self._stop_requested = True
                        self._print_stop_block(
                            state.value,
                            attempt_number,
                            total - attempt_number,
                            "SECURITY_CHALLENGE",
                        )
                        break

            finally:
                if page is not None:
                    try:
                        page.close()
                    except Exception:
                        pass
                if context is not None:
                    try:
                        context.close()
                    except Exception:
                        pass
                browser.close()

        return results

    def _print_stop_block(
        self, result_label: str, entry_number: int, remaining: int, stop_reason: str,
        matched_value: Optional[str] = None,
    ) -> None:
        """Print a standardized stop summary for terminal output.

        ``matched_value`` (the working candidate password) is printed to the
        terminal ONLY on a confirmed success, for the operator's own
        authorized testing. It is never written to the CSV report or any log.
        """
        border = "=" * 60
        if remaining > 0:
            further = (
                f"NOT PROCESSED ({remaining} remaining: entries "
                f"{entry_number + 1}..{entry_number + remaining})"
            )
        else:
            further = "NONE (this was the final entry)"
        print()
        print(border)
        print(f"Authentication result: {result_label}")
        print(f"Matched test fixture: entry #{entry_number}")
        if matched_value is not None:
            print(f"Matched password (terminal only): {matched_value}")
        print(f"Further test entries: {further}")
        print(f"Stop reason: {stop_reason}")
        print(border)
    
    def _launch_browser(self, playwright) -> Browser:
        """Launch the configured browser (delegates to browser helpers)."""
        return browser_helpers.launch_browser(
            playwright,
            browser=self.config.browser.browser.value,
            headless=self.config.browser.headless,
        )
    
    def _run_single_test(
        self,
        page: Page,
        password: str,
        attempt_number: int,
        total_entries: int = 1,
    ) -> TestRunResult:
        """Run a single authentication test attempt.
        
        Args:
            page: Playwright page.
            password: Password to test.
            attempt_number: Attempt number (1-based).
            
        Returns:
            TestRunResult with classification and diagnostics.
        """
        start_time = time.perf_counter()
        navigation_error = False
        error_message = ""
        
        # Reset state for this attempt
        self._observed_http_status = None
        self._login_page_status = None
        self._auth_response_status = None
        self._security_challenge_detected = None
        self._redirect_chain = []
        self._page_title = ""
        self._form_detected = False
        self._selector_diagnostic = ""

        try:
            # 1. Navigate to login page
            print(f"\n[Attempt {attempt_number}] Navigating to {self.config.target_url}")
            response = page.goto(
                self.config.target_url,
                wait_until="domcontentloaded",
                timeout=self.config.browser.navigation_timeout_ms
            )
            
            # Track login page main document status
            if response:
                self._login_page_status = response.status
                print(f"[Entry {attempt_number}/{total_entries}] Login page response: HTTP {response.status}")
            
            # If login page itself returns 404, stop immediately
            if self._login_page_status == 404:
                elapsed = int((time.perf_counter() - start_time) * 1000)
                self._page_title = page.title() if page else ""
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.LOGIN_PAGE_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary="Login page returned HTTP 404 (main document)"
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=False,
                    selector_diagnostic="Login page not found (404)",
                    navigation_error=True,
                    error_message="Login page returned HTTP 404"
                )
            
            # Get page title
            try:
                self._page_title = page.title()
            except Exception:
                pass
            
            # 2. Validate and fill username field with diagnostics
            print(f"[Entry {attempt_number}/{total_entries}] Waiting for username field...")
            selector_diag = self._wait_for_selector_with_diagnostics(
                page, 
                self.config.auth.username_selector, 
                "username",
                self.config.browser.navigation_timeout_ms
            )
            if selector_diag:
                self._selector_diagnostic = selector_diag
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.SELECTOR_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=f"Username selector issue: {selector_diag}"
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=False,
                    selector_diagnostic=selector_diag,
                    navigation_error=True,
                    error_message=f"Username selector not found: {selector_diag}"
                )
            
            page.locator(self.config.auth.username_selector).fill(self.config.auth.username)
            print(f"[Entry {attempt_number}/{total_entries}] Username field filled")
            
            # 3. Validate and fill password field with diagnostics
            print(f"[Entry {attempt_number}/{total_entries}] Waiting for password field...")
            selector_diag = self._wait_for_selector_with_diagnostics(
                page, 
                self.config.auth.password_selector, 
                "password",
                self.config.browser.navigation_timeout_ms
            )
            if selector_diag:
                self._selector_diagnostic = selector_diag
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.SELECTOR_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=f"Password selector issue: {selector_diag}"
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=False,
                    selector_diagnostic=selector_diag,
                    navigation_error=True,
                    error_message=f"Password selector not found: {selector_diag}"
                )
            
            page.locator(self.config.auth.password_selector).fill(password)
            print(f"[Entry {attempt_number}/{total_entries}] Password field filled")
            
            # 4. Validate submit selector
            print(f"[Entry {attempt_number}/{total_entries}] Validating submit button...")
            selector_diag = self._wait_for_selector_with_diagnostics(
                page, 
                self.config.auth.submit_selector, 
                "submit",
                self.config.browser.navigation_timeout_ms
            )
            if selector_diag:
                self._selector_diagnostic = selector_diag
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.SELECTOR_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=f"Submit selector issue: {selector_diag}"
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=False,
                    selector_diagnostic=selector_diag,
                    navigation_error=True,
                    error_message=f"Submit selector not found: {selector_diag}"
                )
            
            self._form_detected = True
            
            # 5. Configurable delay before submit
            delay = self.config.browser.delay_before_submit_seconds
            if delay > 0:
                print(f"[Entry {attempt_number}/{total_entries}] Waiting {delay}s before submit...")
                time.sleep(delay)
            
            # 6. Check for pre-existing security challenges
            challenge = self.detector.check_page_content(page)
            if challenge and challenge.detected:
                self._security_challenge_detected = challenge
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
                        confidence="high",
                        diagnostic_summary=challenge.diagnostic_summary
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=challenge,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=self._form_detected,
                    selector_diagnostic="",
                    navigation_error=False,
                    error_message=""
                )
            
            # 5a. Verify the origin is still an allowlisted host immediately
            # before interacting/submitting. Never submit if the page moved to
            # a host not in allowed_hosts (e.g. an external redirect).
            if not self._check_host_allowed(page.url):
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.UNAUTHORIZED_HOST_BLOCKED,
                        confidence="high",
                        diagnostic_summary=(
                            "Refusing to submit credentials: page is not on a "
                            f"permitted local origin ({page.url})."
                        ),
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=self._form_detected,
                    selector_diagnostic="",
                    navigation_error=True,
                    error_message="Non-local origin before submit",
                )

            # 7. Submit the form
            print(f"[Entry {attempt_number}/{total_entries}] Submitting login form...")
            page.locator(self.config.auth.submit_selector).click()
            
            # 8. Wait for navigation/response
            try:
                page.wait_for_load_state(
                    "domcontentloaded", 
                    timeout=5000
                )
            except Exception:
                pass  # Continue even if load state times out
            
            # Small wait for any dynamic content
            page.wait_for_timeout(1000)
            
            # Update page title after navigation
            try:
                self._page_title = page.title()
            except Exception:
                pass
            
            # Check if navigation went to an unauthorized host
            if not self._check_host_allowed(page.url):
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.UNAUTHORIZED_HOST_BLOCKED,
                        confidence="high",
                        diagnostic_summary=f"Navigation to unauthorized host: {page.url}"
                    ),
                    http_status=self._observed_http_status,
                    login_page_status=self._login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=self._page_title,
                    redirect_chain=self._redirect_chain,
                    form_detected=self._form_detected,
                    selector_diagnostic="",
                    navigation_error=True,
                    error_message=f"Navigation to unauthorized host: {page.url}"
                )
            
            # 9. Check for security challenges after submit
            challenge = self.detector.check_page_content(page)
            if challenge and challenge.detected:
                self._security_challenge_detected = challenge
            
            # Also check navigation URL
            nav_challenge = self.detector.check_navigation(page)
            if nav_challenge and nav_challenge.detected:
                self._security_challenge_detected = nav_challenge
            
            elapsed = int((time.perf_counter() - start_time) * 1000)

            # Determine whether the browser actually navigated off the login
            # page (used by the operator-defined success signal).
            navigated_away = self._navigated_off_login(page.url)

            # 10. Classify the result
            classification = self.classifier.classify(
                page=page,
                http_status=self._observed_http_status,
                security_challenge=(
                    self._security_challenge_detected.challenge_type 
                    if self._security_challenge_detected else None
                ),
                navigation_error=navigation_error,
                login_page_status=self._login_page_status,
                selector_diagnostic=self._selector_diagnostic,
                form_ready=self._form_detected,
                navigated_away=navigated_away
            )
            
            return TestRunResult(
                password_index=attempt_number - 1,
                classification=classification,
                http_status=self._observed_http_status,
                login_page_status=self._login_page_status,
                auth_response_status=self._auth_response_status,
                security_challenge=self._security_challenge_detected,
                elapsed_time_ms=elapsed,
                final_page_url=page.url,
                page_title=self._page_title,
                redirect_chain=self._redirect_chain,
                form_detected=self._form_detected,
                selector_diagnostic=self._selector_diagnostic,
                navigation_error=navigation_error,
                error_message=error_message
            )
            
        except Exception as e:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            navigation_error = True
            error_message = f"{type(e).__name__}: {str(e)[:200]}"
            print(f"[Entry {attempt_number}/{total_entries}] Error: {error_message}")
            
            # Provide better diagnostics for selector timeouts
            if "Timeout" in str(e) and "wait_for" in str(e):
                selector_diag = self._extract_selector_from_error(str(e))
                self._selector_diagnostic = selector_diag
                classification = ClassificationResult(
                    result=AuthenticationResult.SELECTOR_NOT_FOUND,
                    confidence="high",
                    diagnostic_summary=f"Selector timeout: {selector_diag}"
                )
            else:
                classification = ClassificationResult(
                    result=AuthenticationResult.NAVIGATION_ERROR,
                    confidence="high",
                    diagnostic_summary=error_message
                )
            
            try:
                final_url = page.url
                page_title = page.title() if page else ""
            except Exception:
                final_url = ""
                page_title = ""
            
            return TestRunResult(
                password_index=attempt_number - 1,
                classification=classification,
                http_status=self._observed_http_status,
                login_page_status=self._login_page_status,
                auth_response_status=self._auth_response_status,
                security_challenge=self._security_challenge_detected,
                elapsed_time_ms=elapsed,
                final_page_url=final_url,
                page_title=page_title,
                redirect_chain=self._redirect_chain,
                form_detected=self._form_detected,
                selector_diagnostic=self._selector_diagnostic,
                navigation_error=navigation_error,
                error_message=error_message
            )
    
    def _wait_for_selector_with_diagnostics(
        self, 
        page: Page, 
        selector: str, 
        field_name: str,
        timeout: int
    ) -> Optional[str]:
        """Wait for a selector with detailed diagnostics (delegates to helpers).
        
        Returns:
            Diagnostic string if selector issue found, None if successful.
        """
        return browser_helpers.wait_for_selector_with_diagnostics(
            page, selector, field_name, timeout
        )

    def _on_response(self, response: Response):
        """Handle HTTP response for security monitoring."""
        # Only track auth-related responses
        request_url = response.url.lower()
        auth_keywords = ("login", "auth", "session", "callback", "signin", "sign-in")
        
        if any(keyword in request_url for keyword in auth_keywords):
            self._observed_http_status = response.status
            
            # Check for security challenge in response
            challenge = self.detector.check_response(response)
            if challenge and challenge.detected:
                self._security_challenge_detected = challenge
    
    def _write_report(
        self, 
        result: TestRunResult, 
        passwords: PasswordFileResult,
        attempt_number: int
    ):
        """Write test result to CSV report."""
        record = self.reporter.create_record(
            target_url=self.config.target_url,
            auth_provider=self.config.auth.provider.value,
            attempt_number=attempt_number,
            total_entries=passwords.count,
            result=result.classification.result,
            http_status=result.http_status,
            login_page_status=result.login_page_status,
            auth_response_status=result.auth_response_status,
            security_challenge_detected=(
                result.security_challenge.detected 
                if result.security_challenge else False
            ),
            elapsed_time_ms=result.elapsed_time_ms,
            final_page_url=result.final_page_url,
            page_title=result.page_title,
            form_detected=result.form_detected,
            selector_diagnostic=result.selector_diagnostic,
            diagnostic_summary=result.classification.diagnostic_summary,
            secrets=passwords.passwords,
            candidate_password=(
                passwords.passwords[attempt_number - 1]
                if 0 <= attempt_number - 1 < passwords.count else None
            ),
            include_password_in_report=self.config.include_password_in_report,
        )
        
        report_path = self.reporter.write_record(record)
        print(f"[Entry {attempt_number}/{passwords.count}] Report written to: {report_path}")
    
    def print_summary(self, results: List[TestRunResult]):
        """Print a summary of all test results."""
        print("\n" + "=" * 60)
        print("=" * 60)
        
        for result in results:
            attempt = result.password_index + 1
            cls = result.classification
            
            print(f"\nAttempt {attempt}:")
            print(f"  Result:      {cls.result.value}")
            print(f"  Confidence:  {cls.confidence}")
            print(f"  Time:        {result.elapsed_time_ms}ms")
            print(f"  HTTP Status: {result.http_status or 'Not observed'}")
            
            if result.security_challenge and result.security_challenge.detected:
                print(f"  Challenge:   {result.security_challenge.challenge_type}")
                print(f"  Details:     {result.security_challenge.diagnostic_summary}")
            
            if cls.indicators:
                print(f"  Indicators:  {', '.join(cls.indicators)}")
            
            print(f"  Summary:     {cls.diagnostic_summary}")
        
        print("\n" + "=" * 60)


def run_auth_test(
    config: AppConfig,
    override_password: Optional[str] = None,
) -> List[TestRunResult]:
    """Run the authentication test sequence.

    Reads the entire password file (or uses a single provided credential) and
    processes every entry once in file order against the configured target.

    Args:
        config: Application configuration.
        override_password: Optional single credential supplied at run time
            (e.g. from an env var / Credential Manager / prompt). When given,
            it is used as the only candidate; it is never written to disk.

    Returns:
        List of test run results.
    """
    if override_password is not None:
        passwords = PasswordFileResult(
            passwords=[override_password],
            count=1,
            source_path="<provided-at-runtime>",
        )
    else:
        # Validate and read the full password file before launching a browser.
        print("Validating password file...")
        passwords = read_password_file(config.password_file)
        print(f"Password file valid: {passwords.count} entr"
              f"{'y' if passwords.count == 1 else 'ies'} loaded from {passwords.source_path}")

    tester = AuthTester(config)
    results = tester.run(passwords)

    return results