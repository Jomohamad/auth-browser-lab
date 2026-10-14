"""Result classification for authentication testing outcomes.

This module provides explicit result classification based on observed
indicators rather than inferring success from HTTP status codes alone.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from playwright.sync_api import Page

from .config import AuthConfig, ResultCategory


class AuthenticationResult(Enum):
    """Explicit authentication result categories."""
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


@dataclass
class ClassificationResult:
    """Result of authentication classification."""
    result: AuthenticationResult
    confidence: str  # "high", "medium", "low"
    indicators: List[str] = None
    diagnostic_summary: str = ""
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []


class ResultClassifier:
    """Classifies authentication test outcomes using explicit indicators."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
    
    def classify(
        self,
        page: Page,
        http_status: Optional[int],
        security_challenge: Optional[str],
        navigation_error: bool = False,
        login_page_status: Optional[int] = None,
        selector_diagnostic: Optional[str] = None,
        form_ready: bool = True,
        navigated_away: bool = False,
    ) -> ClassificationResult:
        """Classify the authentication outcome.
        
        Args:
            page: Playwright page after authentication attempt.
            http_status: HTTP status from auth-related response.
            security_challenge: Type of security challenge detected, if any.
            navigation_error: Whether a navigation error occurred.
            login_page_status: HTTP status of the main login page document.
            selector_diagnostic: Diagnostic info about selector matching.
            form_ready: Whether the login form was detected and ready.
            
        Returns:
            ClassificationResult with explicit classification.
        """
        # Login page not found (main document 404)
        if login_page_status == 404:
            return ClassificationResult(
                result=AuthenticationResult.LOGIN_PAGE_NOT_FOUND,
                confidence="high",
                diagnostic_summary="Login page returned HTTP 404 (main document)"
            )
        
        # Selector not found
        if selector_diagnostic:
            return ClassificationResult(
                result=AuthenticationResult.SELECTOR_NOT_FOUND,
                confidence="high",
                diagnostic_summary=f"Selector issue: {selector_diagnostic}"
            )
        
        # Form not ready
        if not form_ready:
            return ClassificationResult(
                result=AuthenticationResult.FORM_NOT_READY,
                confidence="high",
                diagnostic_summary="Login form not detected or not ready"
            )
        
        if navigation_error:
            return ClassificationResult(
                result=AuthenticationResult.NAVIGATION_ERROR,
                confidence="high",
                diagnostic_summary="Navigation failed or timed out"
            )
        
        # Security challenges take precedence
        if security_challenge:
            return self._classify_security_challenge(security_challenge)

        # A confirmed failure (error element / invalid-credentials text) must
        # take precedence over success, so a login or error page is never
        # reported as a successful login.
        failure_result = self._check_failure_indicators(page)
        if failure_result:
            return failure_result

        # Success is only asserted when an explicit success indicator is seen
        # (authenticated URL path or authenticated-only element). A bare HTTP
        # 302/redirect is intentionally NOT treated as success here.
        success_result = self._check_success_indicators(page)
        if success_result:
            return success_result

        # Operator-defined success signal: for apps where the login error
        # element is the sole correctness indicator, a submit that navigated
        # off the login page with no failure element is a confirmed success.
        # (Failure was already ruled out above.)
        if self.config.success_on_navigation_without_failure and navigated_away:
            return ClassificationResult(
                result=AuthenticationResult.SUCCESS_CONFIRMED,
                confidence="medium",
                indicators=["Navigated off login page with no failure indicator"],
                diagnostic_summary=(
                    "Operator-defined success: page navigated away from the "
                    "login page with no configured failure indicator."
                )
            )
        
        # Check HTTP status as secondary indicator
        http_result = self._check_http_status(http_status)
        if http_result:
            return http_result
        
        # Default to inconclusive - requires manual review
        return ClassificationResult(
            result=AuthenticationResult.INCONCLUSIVE,
            confidence="low",
            diagnostic_summary=(
                "No explicit success or failure indicators found. "
                "Manual review of browser state required."
            )
        )
    
    def _classify_security_challenge(self, challenge_type: str) -> ClassificationResult:
        """Classify based on security challenge type."""
        challenge_map = {
            "RATE_LIMIT": AuthenticationResult.STOPPED_RATE_LIMIT,
            "CAPTCHA": AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
            "MFA_CHALLENGE": AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
            "ACCOUNT_LOCKOUT": AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
            "ACCESS_DENIED": AuthenticationResult.STOPPED_ACCESS_DENIED,
            "HTTP_429": AuthenticationResult.STOPPED_RATE_LIMIT,
            "HTTP_403": AuthenticationResult.STOPPED_ACCESS_DENIED,
            "SECURITY_CHALLENGE": AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
            "URL_CHALLENGE_INDICATOR": AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
        }
        
        result = challenge_map.get(challenge_type, AuthenticationResult.STOPPED_SECURITY_CHALLENGE)
        
        return ClassificationResult(
            result=result,
            confidence="high",
            indicators=[challenge_type],
            diagnostic_summary=f"Security challenge detected: {challenge_type}"
        )
    
    def _check_success_indicators(self, page: Page) -> Optional[ClassificationResult]:
        """Check for explicit success indicators."""
        indicators = []
        
        # Check URL patterns
        current_url = page.url
        for pattern in self.config.success_url_patterns:
            if pattern in current_url:
                indicators.append(f"URL pattern matched: {pattern}")
        
        # Check success selectors
        for selector in self.config.success_selectors:
            try:
                if page.locator(selector).count() > 0:
                    indicators.append(f"Success selector found: {selector}")
            except Exception:
                pass
        
        if indicators:
            return ClassificationResult(
                result=AuthenticationResult.SUCCESS_CONFIRMED,
                confidence="high",
                indicators=indicators,
                diagnostic_summary="Explicit success indicators observed"
            )
        
        return None
    
    def _check_failure_indicators(self, page: Page) -> Optional[ClassificationResult]:
        """Check for explicit authentication failure indicators."""
        indicators = []
        
        # Check failure selectors
        for selector in self.config.failure_selectors:
            try:
                if page.locator(selector).count() > 0:
                    # Get the error text for diagnostics
                    try:
                        error_text = page.locator(selector).inner_text()
                        indicators.append(f"Failure selector: {selector} - '{error_text[:100]}'")
                    except Exception:
                        indicators.append(f"Failure selector found: {selector}")
            except Exception:
                pass
        
        # Check page text for common failure messages
        try:
            body_text = page.locator("body").inner_text().lower()
            failure_patterns = [
                "invalid credentials",
                "incorrect password",
                "wrong password",
                "invalid email",
                "invalid username",
                "authentication failed",
                "login failed",
                "sign in failed",
                "unauthorized",
            ]
            for pattern in failure_patterns:
                if pattern in body_text:
                    indicators.append(f"Failure text pattern: {pattern}")
        except Exception:
            pass
        
        if indicators:
            return ClassificationResult(
                result=AuthenticationResult.AUTHENTICATION_FAILED,
                confidence="high",
                indicators=indicators,
                diagnostic_summary="Explicit authentication failure indicators observed"
            )
        
        return None
    
    def _check_http_status(self, status: Optional[int]) -> Optional[ClassificationResult]:
        """Check HTTP status as secondary indicator.
        
        Note: We never classify success based solely on HTTP status.
        """
        if status is None:
            return None
        
        # HTTP 200 alone doesn't mean success
        # HTTP 401/403 on auth endpoint might indicate failure
        # But we rely on explicit indicators first
        
        return None


def create_classifier(config: AuthConfig) -> ResultClassifier:
    """Factory function to create a result classifier.
    
    Args:
        config: Authentication configuration.
        
    Returns:
        Configured ResultClassifier instance.
    """
    return ResultClassifier(config)