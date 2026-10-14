"""Security challenge detection for authentication testing.

This module detects various security challenges, rate limits, CAPTCHAs,
and other blocking mechanisms during authentication testing.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

from playwright.sync_api import Page, Response

from .config import SecurityChallengeConfig


@dataclass
class SecurityChallengeResult:
    """Result of security challenge detection."""
    detected: bool = False
    challenge_type: str = ""
    http_status: Optional[int] = None
    matched_patterns: List[str] = field(default_factory=list)
    matched_selectors: List[str] = field(default_factory=list)
    diagnostic_summary: str = ""


class SecurityChallengeDetector:
    """Detects security challenges during authentication flow."""
    
    def __init__(self, config: SecurityChallengeConfig):
        self.config = config
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in config.blocking_text_patterns
        ]
    
    def check_response(self, response: Response) -> Optional[SecurityChallengeResult]:
        """Check HTTP response for security challenges.
        
        Args:
            response: Playwright response object.
            
        Returns:
            SecurityChallengeResult if challenge detected, None otherwise.
        """
        # Only check authentication-related responses
        request_url = response.url.lower()
        auth_keywords = ("login", "auth", "session", "callback", "signin", "sign-in")
        
        if not any(keyword in request_url for keyword in auth_keywords):
            return None
        
        if response.status in self.config.http_status_codes:
            challenge_type = self._classify_http_status(response.status)
            return SecurityChallengeResult(
                detected=True,
                challenge_type=challenge_type,
                http_status=response.status,
                diagnostic_summary=(
                    f"HTTP {response.status} on auth-related request: {response.url}"
                )
            )
        
        return None
    
    def check_page_content(self, page: Page) -> Optional[SecurityChallengeResult]:
        """Check page content for security challenges.
        
        Args:
            page: Playwright page object.
            
        Returns:
            SecurityChallengeResult if challenge detected, None otherwise.
        """
        # Get page text content
        try:
            body_text = page.locator("body").inner_text()
        except Exception:
            body_text = ""
        
        body_lower = body_text.lower()
        matched_patterns = []
        
        # Check text patterns
        for pattern, compiled in zip(self.config.blocking_text_patterns, self._compiled_patterns):
            if compiled.search(body_lower):
                matched_patterns.append(pattern)
        
        # Check for CAPTCHA elements
        matched_selectors = []
        for selector in self.config.captcha_selectors:
            try:
                if page.locator(selector).count() > 0:
                    matched_selectors.append(selector)
            except Exception:
                pass
        
        # Check for MFA elements (outside configured flow)
        mfa_detected = False
        for selector in self.config.mfa_selectors:
            try:
                if page.locator(selector).count() > 0:
                    matched_selectors.append(selector)
                    mfa_detected = True
            except Exception:
                pass
        
        if matched_patterns or matched_selectors:
            challenge_type = self._classify_challenge(matched_patterns, mfa_detected)
            return SecurityChallengeResult(
                detected=True,
                challenge_type=challenge_type,
                matched_patterns=matched_patterns,
                matched_selectors=matched_selectors,
                diagnostic_summary=self._build_summary(
                    matched_patterns, matched_selectors, mfa_detected
                )
            )
        
        return None
    
    def check_navigation(self, page: Page) -> Optional[SecurityChallengeResult]:
        """Check for security challenges after navigation.
        
        Args:
            page: Playwright page object after navigation.
            
        Returns:
            SecurityChallengeResult if challenge detected, None otherwise.
        """
        # Check URL for challenge indicators
        current_url = page.url.lower()
        challenge_indicators = [
            "captcha",
            "challenge",
            "blocked",
            "rate-limit",
            "rate_limit",
            "access-denied",
            "access_denied",
            "too-many",
            "too_many",
            "suspended",
            "locked",
            "verify",
            "mfa",
            "2fa",
            "two-factor",
        ]
        
        for indicator in challenge_indicators:
            if indicator in current_url:
                return SecurityChallengeResult(
                    detected=True,
                    challenge_type="URL_CHALLENGE_INDICATOR",
                    diagnostic_summary=f"Challenge indicator in URL: {indicator}"
                )
        
        return None
    
    def _classify_http_status(self, status: int) -> str:
        """Classify HTTP status code."""
        if status == 429:
            return "RATE_LIMIT"
        elif status == 403:
            return "ACCESS_DENIED"
        return f"HTTP_{status}"
    
    def _classify_challenge(
        self, 
        patterns: List[str], 
        mfa_detected: bool
    ) -> str:
        """Classify the type of security challenge."""
        if mfa_detected:
            return "MFA_CHALLENGE"
        if any("captcha" in p for p in patterns):
            return "CAPTCHA"
        if any("rate limit" in p or "too many" in p for p in patterns):
            return "RATE_LIMIT"
        if any("blocked" in p or "locked" in p for p in patterns):
            return "ACCOUNT_LOCKOUT"
        if any("access denied" in p for p in patterns):
            return "ACCESS_DENIED"
        return "SECURITY_CHALLENGE"
    
    def _build_summary(
        self, 
        patterns: List[str], 
        selectors: List[str], 
        mfa_detected: bool
    ) -> str:
        """Build diagnostic summary."""
        parts = []
        if patterns:
            parts.append(f"Text patterns: {', '.join(patterns)}")
        if selectors:
            parts.append(f"Selectors: {', '.join(selectors)}")
        if mfa_detected:
            parts.append("MFA challenge detected")
        return "; ".join(parts) if parts else "Security challenge detected"


def create_detector(config: SecurityChallengeConfig) -> SecurityChallengeDetector:
    """Factory function to create a security challenge detector.
    
    Args:
        config: Security challenge configuration.
        
    Returns:
        Configured SecurityChallengeDetector instance.
    """
    return SecurityChallengeDetector(config)