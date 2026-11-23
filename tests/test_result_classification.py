# Signed by JOE
"""Unit tests for result classification and security challenge detection."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from playwright.sync_api import Page, Response

from auth_audit.config import (
    AuthConfig,
    SecurityChallengeConfig,
    ResultCategory,
)
from auth_audit.result_classifier import ResultClassifier, ClassificationResult, create_classifier, AuthenticationResult
from auth_audit.security import (
    SecurityChallengeDetector, 
    SecurityChallengeResult, 
    create_detector
)


class TestResultClassifier:
    """Tests for authentication result classification."""
    
    @pytest.fixture
    def auth_config(self):
        """Create a test auth configuration."""
        return AuthConfig(
            provider="custom",
            username="test@example.com",
            username_selector='input[name="email"]',
            password_selector='input[name="password"]',
            submit_selector='button[type="submit"]',
            success_url_patterns=["/dashboard", "/home"],
            success_selectors=[".user-menu", "[data-testid='user-profile']"],
            failure_selectors=[".error-message", "[data-testid='auth-error']"]
        )
    
    @pytest.fixture
    def classifier(self, auth_config):
        """Create a result classifier."""
        return ResultClassifier(auth_config)
    
    @pytest.fixture
    def mock_page(self):
        """Create a mock Playwright page."""
        page = Mock(spec=Page)
        page.url = "https://example.com/dashboard"
        page.locator = Mock()
        return page
    
    def test_classify_success_by_url_pattern(self, classifier, mock_page):
        """Test classification as success when URL pattern matches."""
        mock_page.url = "https://example.com/dashboard"
        mock_page.locator.return_value.count.return_value = 0
        
        result = classifier.classify(mock_page, http_status=200, security_challenge=None)
        
        assert result.result == AuthenticationResult.SUCCESS_CONFIRMED
        assert result.confidence == "high"
        assert any("URL pattern matched" in ind for ind in result.indicators)
    
    def test_classify_success_by_selector(self, classifier, mock_page):
        """Test classification as success when only a success selector matches."""
        mock_page.url = "https://example.com/some-page"

        def locator_side_effect(selector):
            mock_loc = Mock()
            if selector in (".user-menu", "[data-testid='user-profile']"):
                mock_loc.count.return_value = 1
            else:
                mock_loc.count.return_value = 0
            return mock_loc

        mock_page.locator.side_effect = locator_side_effect

        result = classifier.classify(mock_page, http_status=200, security_challenge=None)

        assert result.result == AuthenticationResult.SUCCESS_CONFIRMED
        assert result.confidence == "high"
    
    def test_classify_authentication_failed_by_selector(self, classifier, mock_page):
        """Test classification as failed when failure selector found."""
        mock_page.url = "https://example.com/login"
        # Configure locator to return failure selector count > 0
        def locator_side_effect(selector):
            mock_loc = Mock()
            if selector in [".error-message", "[data-testid='auth-error']"]:
                mock_loc.count.return_value = 1
                mock_loc.inner_text.return_value = "Invalid credentials"
            else:
                mock_loc.count.return_value = 0
            return mock_loc
        
        mock_page.locator.side_effect = locator_side_effect
        
        result = classifier.classify(mock_page, http_status=200, security_challenge=None)
        
        assert result.result == AuthenticationResult.AUTHENTICATION_FAILED
        assert result.confidence == "high"
    
    def test_classify_authentication_failed_by_text(self, classifier, mock_page):
        """Test classification as failed when failure text pattern found."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        mock_page.locator.return_value.inner_text.return_value = "Invalid credentials, please try again"
        
        result = classifier.classify(mock_page, http_status=200, security_challenge=None)
        
        assert result.result == AuthenticationResult.AUTHENTICATION_FAILED
        assert result.confidence == "high"
    
    def test_classify_stopped_rate_limit(self, classifier, mock_page):
        """Test classification when rate limit detected."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        
        result = classifier.classify(
            mock_page, 
            http_status=429, 
            security_challenge="RATE_LIMIT"
        )
        
        assert result.result == AuthenticationResult.STOPPED_RATE_LIMIT
        assert result.confidence == "high"
    
    def test_classify_stopped_captcha(self, classifier, mock_page):
        """Test classification when CAPTCHA detected."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        
        result = classifier.classify(
            mock_page, 
            http_status=200, 
            security_challenge="CAPTCHA"
        )
        
        assert result.result == AuthenticationResult.STOPPED_SECURITY_CHALLENGE
        assert result.confidence == "high"
    
    def test_classify_stopped_mfa(self, classifier, mock_page):
        """Test classification when MFA challenge detected."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        
        result = classifier.classify(
            mock_page, 
            http_status=200, 
            security_challenge="MFA_CHALLENGE"
        )
        
        assert result.result == AuthenticationResult.STOPPED_SECURITY_CHALLENGE
        assert result.confidence == "high"
    
    def test_classify_stopped_access_denied(self, classifier, mock_page):
        """Test classification when access denied detected."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        
        result = classifier.classify(
            mock_page, 
            http_status=403, 
            security_challenge="ACCESS_DENIED"
        )
        
        assert result.result == AuthenticationResult.STOPPED_ACCESS_DENIED
        assert result.confidence == "high"
    
    def test_classify_navigation_error(self, classifier, mock_page):
        """Test classification when navigation error occurred."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        
        result = classifier.classify(
            mock_page, 
            http_status=None, 
            security_challenge=None,
            navigation_error=True
        )
        
        assert result.result == AuthenticationResult.NAVIGATION_ERROR
        assert result.confidence == "high"
    
    def test_classify_inconclusive_when_ambiguous(self, classifier, mock_page):
        """Test classification as inconclusive when no clear indicators."""
        mock_page.url = "https://example.com/login"
        mock_page.locator.return_value.count.return_value = 0
        mock_page.locator.return_value.inner_text.return_value = "Welcome to the login page"
        
        result = classifier.classify(
            mock_page, 
            http_status=200, 
            security_challenge=None
        )
        
        assert result.result == AuthenticationResult.INCONCLUSIVE
        assert result.confidence == "low"
        assert "Manual review" in result.diagnostic_summary
    
    def test_security_challenge_takes_precedence_over_success(self, classifier, mock_page):
        """Test that security challenge overrides success indicators."""
        mock_page.url = "https://example.com/dashboard"  # Success URL
        mock_page.locator.return_value.count.return_value = 1  # Success selector found
        
        result = classifier.classify(
            mock_page, 
            http_status=200, 
            security_challenge="CAPTCHA"  # But CAPTCHA detected
        )
        
        assert result.result == AuthenticationResult.STOPPED_SECURITY_CHALLENGE
        assert result.confidence == "high"


class TestSecurityChallengeDetector:
    """Tests for security challenge detection."""
    
    @pytest.fixture
    def security_config(self):
        """Create a test security configuration."""
        return SecurityChallengeConfig(
            http_status_codes=[403, 429],
            blocking_text_patterns=[
                "too many attempts",
                "rate limit",
                "captcha",
                "temporarily blocked",
                "account locked"
            ],
            captcha_selectors=[".captcha", "#recaptcha"],
            mfa_selectors=[".mfa-challenge", "[data-testid='mfa']"]
        )
    
    @pytest.fixture
    def detector(self, security_config):
        """Create a security challenge detector."""
        return SecurityChallengeDetector(security_config)
    
    @pytest.fixture
    def mock_response(self):
        """Create a mock Playwright response."""
        response = Mock(spec=Response)
        response.url = "https://example.com/api/login"
        response.status = 200
        return response
    
    @pytest.fixture
    def mock_page(self):
        """Create a mock Playwright page."""
        page = Mock(spec=Page)
        page.url = "https://example.com/login"
        page.locator = Mock()
        return page
    
    def test_check_response_429_rate_limit(self, detector, mock_response):
        """Test detection of HTTP 429 rate limit."""
        mock_response.status = 429
        mock_response.url = "https://example.com/api/login"
        
        result = detector.check_response(mock_response)
        
        assert result is not None
        assert result.detected is True
        assert result.challenge_type == "RATE_LIMIT"
        assert result.http_status == 429
    
    def test_check_response_403_access_denied(self, detector, mock_response):
        """Test detection of HTTP 403 access denied."""
        mock_response.status = 403
        mock_response.url = "https://example.com/api/auth/callback"
        
        result = detector.check_response(mock_response)
        
        assert result is not None
        assert result.detected is True
        assert result.challenge_type == "ACCESS_DENIED"
        assert result.http_status == 403
    
    def test_check_response_ignores_non_auth_endpoints(self, detector, mock_response):
        """Test that non-auth endpoints are ignored."""
        mock_response.status = 403
        mock_response.url = "https://example.com/static/image.png"
        
        result = detector.check_response(mock_response)
        
        assert result is None
    
    def test_check_response_ignores_200_on_auth_endpoint(self, detector, mock_response):
        """Test that HTTP 200 on auth endpoint is not a challenge."""
        mock_response.status = 200
        mock_response.url = "https://example.com/api/login"
        
        result = detector.check_response(mock_response)
        
        assert result is None
    
    def test_check_page_content_detects_blocking_text(self, detector, mock_page):
        """Test detection of blocking text patterns in page content."""
        mock_page.locator.return_value.inner_text.return_value = (
            "Too many attempts. Please try again later."
        )
        mock_page.locator.return_value.count.return_value = 0
        
        result = detector.check_page_content(mock_page)
        
        assert result is not None
        assert result.detected is True
        assert "too many attempts" in result.matched_patterns
    
    def test_check_page_content_detects_captcha_selector(self, detector, mock_page):
        """Test detection of CAPTCHA via selector."""
        def locator_side_effect(selector):
            mock_loc = Mock()
            if selector == "body":
                mock_loc.inner_text.return_value = "Login page"
            elif selector in [".captcha", "#recaptcha"]:
                mock_loc.count.return_value = 1
            else:
                mock_loc.count.return_value = 0
            return mock_loc
        
        mock_page.locator.side_effect = locator_side_effect
        
        result = detector.check_page_content(mock_page)
        
        assert result is not None
        assert result.detected is True
        assert any("captcha" in s for s in result.matched_selectors)
        assert result.challenge_type == "CAPTCHA"
    
    def test_check_page_content_detects_mfa_selector(self, detector, mock_page):
        """Test detection of MFA challenge via selector."""
        def locator_side_effect(selector):
            mock_loc = Mock()
            if selector == "body":
                mock_loc.inner_text.return_value = "Enter MFA code"
            elif selector in [".mfa-challenge", "[data-testid='mfa']"]:
                mock_loc.count.return_value = 1
            else:
                mock_loc.count.return_value = 0
            return mock_loc
        
        mock_page.locator.side_effect = locator_side_effect
        
        result = detector.check_page_content(mock_page)
        
        assert result is not None
        assert result.detected is True
        assert result.challenge_type == "MFA_CHALLENGE"
    
    def test_check_page_content_no_challenge(self, detector, mock_page):
        """Test no challenge detected on normal page."""
        mock_page.locator.return_value.inner_text.return_value = "Welcome to login"
        mock_page.locator.return_value.count.return_value = 0
        
        result = detector.check_page_content(mock_page)
        
        assert result is None
    
    def test_check_navigation_detects_challenge_url(self, detector, mock_page):
        """Test detection of challenge indicators in URL."""
        mock_page.url = "https://example.com/challenge/captcha"
        
        result = detector.check_navigation(mock_page)
        
        assert result is not None
        assert result.detected is True
        assert result.challenge_type == "URL_CHALLENGE_INDICATOR"
    
    def test_check_navigation_no_challenge(self, detector, mock_page):
        """Test no challenge on normal URL."""
        mock_page.url = "https://example.com/dashboard"
        
        result = detector.check_navigation(mock_page)
        
        assert result is None


class TestFactoryFunctions:
    """Tests for factory functions."""
    
    def test_create_classifier(self):
        """Test create_classifier factory function."""
        config = AuthConfig()
        classifier = create_classifier(config)
        
        assert isinstance(classifier, ResultClassifier)
    
    def test_create_detector(self):
        """Test create_detector factory function."""
        config = SecurityChallengeConfig()
        detector = create_detector(config)
        
        assert isinstance(detector, SecurityChallengeDetector)


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""
    
    def test_classification_result_creation(self):
        """Test creating a ClassificationResult."""
        result = ClassificationResult(
            result=AuthenticationResult.SUCCESS_CONFIRMED,
            confidence="high",
            indicators=["URL matched", "Selector found"],
            diagnostic_summary="Success confirmed"
        )
        
        assert result.result == AuthenticationResult.SUCCESS_CONFIRMED
        assert result.confidence == "high"
        assert len(result.indicators) == 2
        assert result.diagnostic_summary == "Success confirmed"
    
    def test_classification_result_default_indicators(self):
        """Test default empty indicators list."""
        result = ClassificationResult(
            result=AuthenticationResult.INCONCLUSIVE,
            confidence="low"
        )
        
        assert result.indicators == []


class TestSecurityChallengeResult:
    """Tests for SecurityChallengeResult dataclass."""
    
    def test_security_challenge_result_creation(self):
        """Test creating a SecurityChallengeResult."""
        result = SecurityChallengeResult(
            detected=True,
            challenge_type="CAPTCHA",
            http_status=200,
            matched_patterns=["captcha"],
            matched_selectors=[".g-recaptcha"],
            diagnostic_summary="CAPTCHA detected"
        )
        
        assert result.detected is True
        assert result.challenge_type == "CAPTCHA"
        assert result.http_status == 200
        assert "captcha" in result.matched_patterns
        assert ".g-recaptcha" in result.matched_selectors
    
    def test_security_challenge_result_defaults(self):
        """Test default values."""
        result = SecurityChallengeResult()
        
        assert result.detected is False
        assert result.challenge_type == ""
        assert result.http_status is None
        assert result.matched_patterns == []
        assert result.matched_selectors == []
        assert result.diagnostic_summary == ""