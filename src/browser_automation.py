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

from .config import AppConfig, AuthenticationResult, BrowserType, ExecutionMode
from .password_handler import PasswordFileResult, read_password_file
from .reporter import CSVReporter, TestReportRecord
from .result_classifier import ResultClassifier, ClassificationResult
from .security_detector import SecurityChallengeDetector, SecurityChallengeResult


@dataclass
class TestRunResult:
    """Result of a single test run."""
    password_index: int
    classification: ClassificationResult
    http_status: Optional[int]
    security_challenge: Optional[SecurityChallengeResult]
    elapsed_time_ms: int
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
        self._security_challenge_detected: Optional[SecurityChallengeResult] = None
        self._stop_requested: bool = False
    
    def run(self, passwords: PasswordFileResult) -> List[TestRunResult]:
        """Run authentication tests for the provided passwords.
        
        Args:
            passwords: Validated password file result.
            
        Returns:
            List of test run results.
        """
        results = []
        
        with sync_playwright() as p:
            browser = self._launch_browser(p)
            context = browser.new_context()
            
            # Set up response listener
            def handle_response(response: Response):
                self._on_response(response)
            
            context.on("response", handle_response)
            
            try:
                for i, password in enumerate(passwords.passwords):
                    if self._stop_requested:
                        break
                    
                    page = context.new_page()
                    
                    try:
                        result = self._run_single_test(page, password, i + 1)
                        results.append(result)
                        
                        # Write report
                        self._write_report(result, passwords, i + 1)
                        
                        # Stop on security challenge if configured
                        if (self.config.stop_on_security_challenge and 
                            result.security_challenge and 
                            result.security_challenge.detected):
                            self._stop_requested = True
                            print(f"\n[STOP] Security challenge detected. Halting further attempts.")
                            break
                            
                    finally:
                        page.close()
                        
            finally:
                context.close()
                browser.close()
        
        return results
    
    def _launch_browser(self, playwright) -> Browser:
        """Launch the configured browser."""
        browser_type = getattr(playwright, self.config.browser.browser.value)
        
        return browser_type.launch(
            headless=self.config.browser.headless,
            args=["--disable-blink-features=AutomationControlled"] if not self.config.browser.headless else []
        )
    
    def _run_single_test(
        self, 
        page: Page, 
        password: str, 
        attempt_number: int
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
        self._security_challenge_detected = None
        
        try:
            # 1. Navigate to login page
            print(f"\n[Attempt {attempt_number}] Navigating to {self.config.target_url}")
            page.goto(
                self.config.target_url,
                wait_until="domcontentloaded",
                timeout=self.config.browser.navigation_timeout_ms
            )
            
            # 2. Wait for username field and fill
            print(f"[Attempt {attempt_number}] Filling username field...")
            page.locator(self.config.auth.username_selector).wait_for(
                state="visible",
                timeout=self.config.browser.navigation_timeout_ms
            )
            page.locator(self.config.auth.username_selector).fill(self.config.auth.username)
            
            # 3. Wait for password field and fill
            print(f"[Attempt {attempt_number}] Filling password field...")
            page.locator(self.config.auth.password_selector).wait_for(
                state="visible",
                timeout=self.config.browser.navigation_timeout_ms
            )
            page.locator(self.config.auth.password_selector).fill(password)
            
            # 4. Configurable delay before submit
            delay = self.config.browser.delay_before_submit_seconds
            if delay > 0:
                print(f"[Attempt {attempt_number}] Waiting {delay}s before submit...")
                time.sleep(delay)
            
            # 5. Check for pre-existing security challenges
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
                    security_challenge=challenge,
                    elapsed_time_ms=elapsed
                )
            
            # 6. Submit the form
            print(f"[Attempt {attempt_number}] Submitting login form...")
            page.locator(self.config.auth.submit_selector).click()
            
            # 7. Wait for navigation/response
            try:
                page.wait_for_load_state(
                    "domcontentloaded", 
                    timeout=5000
                )
            except Exception:
                pass  # Continue even if load state times out
            
            # Small wait for any dynamic content
            page.wait_for_timeout(1000)
            
            # 8. Check for security challenges after submit
            challenge = self.detector.check_page_content(page)
            if challenge and challenge.detected:
                self._security_challenge_detected = challenge
            
            # Also check navigation URL
            nav_challenge = self.detector.check_navigation(page)
            if nav_challenge and nav_challenge.detected:
                self._security_challenge_detected = nav_challenge
            
            elapsed = int((time.perf_counter() - start_time) * 1000)
            
            # 9. Classify the result
            classification = self.classifier.classify(
                page=page,
                http_status=self._observed_http_status,
                security_challenge=(
                    self._security_challenge_detected.challenge_type 
                    if self._security_challenge_detected else None
                ),
                navigation_error=navigation_error
            )
            
            return TestRunResult(
                password_index=attempt_number - 1,
                classification=classification,
                http_status=self._observed_http_status,
                security_challenge=self._security_challenge_detected,
                elapsed_time_ms=elapsed,
                navigation_error=navigation_error,
                error_message=error_message
            )
            
        except Exception as e:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            navigation_error = True
            error_message = f"{type(e).__name__}: {str(e)[:200]}"
            print(f"[Attempt {attempt_number}] Error: {error_message}")
            
            return TestRunResult(
                password_index=attempt_number - 1,
                classification=ClassificationResult(
                    result=AuthenticationResult.NAVIGATION_ERROR,
                    confidence="high",
                    diagnostic_summary=error_message
                ),
                http_status=self._observed_http_status,
                security_challenge=self._security_challenge_detected,
                elapsed_time_ms=elapsed,
                navigation_error=True,
                error_message=error_message
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
            execution_mode=self.config.execution_mode,
            attempt_number=attempt_number,
            result=result.classification.result,
            http_status=result.http_status,
            security_challenge_detected=(
                result.security_challenge.detected 
                if result.security_challenge else False
            ),
            elapsed_time_ms=result.elapsed_time_ms,
            diagnostic_summary=result.classification.diagnostic_summary
        )
        
        report_path = self.reporter.write_record(record)
        print(f"[Attempt {attempt_number}] Report written to: {report_path}")
    
    def print_summary(self, results: List[TestRunResult]):
        """Print a summary of all test results."""
        print("\n" + "=" * 60)
        print("AUTHENTICATION TEST SUMMARY")
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


def run_auth_test(config: AppConfig) -> List[TestRunResult]:
    """Main entry point for running authentication tests.
    
    Args:
        config: Application configuration.
        
    Returns:
        List of test run results.
    """
    # Validate and read passwords
    print("Validating password file...")
    passwords = read_password_file(
        config.password_file,
        config.execution_mode.value,
        config.maximum_attempts
    )
    print(f"Password file valid: {passwords.count} password(s) for {passwords.mode} mode")
    
    # Run tests
    tester = AuthTester(config)
    results = tester.run(passwords)
    
    # Print summary
    tester.print_summary(results)
    
    return results