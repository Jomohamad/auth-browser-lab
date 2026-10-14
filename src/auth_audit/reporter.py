"""CSV reporting for authentication test results.

This module handles writing sanitized test results to CSV files
without storing any sensitive information.
"""

import csv
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import ExecutionMode
from .result_classifier import AuthenticationResult


@dataclass
class TestReportRecord:
    """Sanitized test report record for CSV output."""
    timestamp_utc: str
    target_host: str
    authentication_provider: str
    execution_mode: str
    attempt_number: int
    result: str
    http_status: Optional[int]
    security_challenge_detected: bool
    elapsed_time_ms: int
    diagnostic_summary: str


class CSVReporter:
    """Handles writing test results to CSV reports."""
    
    def __init__(self, report_directory: str):
        self.report_directory = Path(report_directory)
        self.report_directory.mkdir(parents=True, exist_ok=True)
    
    def write_record(self, record: TestReportRecord) -> Path:
        """Write a single test record to the CSV report.
        
        Args:
            record: TestReportRecord to write.
            
        Returns:
            Path to the report file.
        """
        # Generate filename with date
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        report_file = self.report_directory / f"auth-test-{date_str}.csv"
        
        file_exists = report_file.exists()
        is_empty = file_exists and report_file.stat().st_size == 0
        
        fieldnames = [
            "timestamp_utc",
            "target_host",
            "authentication_provider",
            "execution_mode",
            "attempt_number",
            "result",
            "http_status",
            "security_challenge_detected",
            "elapsed_time_ms",
            "diagnostic_summary"
        ]
        
        with report_file.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            if not file_exists or is_empty:
                writer.writeheader()
            
            writer.writerow(asdict(record))
        
        return report_file
    
    def create_record(
        self,
        target_url: str,
        auth_provider: str,
        execution_mode: ExecutionMode,
        attempt_number: int,
        result: AuthenticationResult,
        http_status: Optional[int],
        security_challenge_detected: bool,
        elapsed_time_ms: int,
        diagnostic_summary: str
    ) -> TestReportRecord:
        """Create a sanitized test report record.
        
        Args:
            target_url: Target URL (hostname extracted).
            auth_provider: Authentication provider name.
            execution_mode: Execution mode.
            attempt_number: Attempt number.
            result: Classification result.
            http_status: HTTP status code.
            security_challenge_detected: Whether security challenge was detected.
            elapsed_time_ms: Test elapsed time in milliseconds.
            diagnostic_summary: Diagnostic summary (sanitized).
            
        Returns:
            TestReportRecord ready for CSV output.
        """
        # Extract hostname only
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        target_host = parsed.hostname or "unknown"
        
        # Sanitize diagnostic summary - ensure no secrets
        sanitized_summary = self._sanitize_summary(diagnostic_summary)
        
        return TestReportRecord(
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            target_host=target_host,
            authentication_provider=auth_provider,
            execution_mode=execution_mode.value,
            attempt_number=attempt_number,
            result=result.value,
            http_status=http_status,
            security_challenge_detected=security_challenge_detected,
            elapsed_time_ms=elapsed_time_ms,
            diagnostic_summary=sanitized_summary
        )
    
    def _sanitize_summary(self, summary: str) -> str:
        """Sanitize diagnostic summary to remove potential secrets.
        
        Args:
            summary: Raw diagnostic summary.
            
        Returns:
            Sanitized summary.
        """
        if not summary:
            return ""
        
        # Remove common secret patterns
        import re
        
        # Remove potential passwords (alphanumeric + special chars, 8+ chars)
        summary = re.sub(r'\b[A-Za-z0-9!@#$%^&*]{8,}\b', '[REDACTED]', summary)
        
        # Remove potential tokens (long alphanumeric strings)
        summary = re.sub(r'\b[a-zA-Z0-9]{32,}\b', '[REDACTED]', summary)
        
        # Remove potential JWT-like strings
        summary = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED]', summary)
        
        # Remove cookie-like patterns
        summary = re.sub(r'(session|token|auth|csrf|xsrf)[=:]\s*[^;\s]+', r'\1=[REDACTED]', summary, flags=re.IGNORECASE)
        
        # Limit length
        if len(summary) > 500:
            summary = summary[:497] + "..."
        
        return summary


def create_reporter(report_directory: str) -> CSVReporter:
    """Factory function to create a CSV reporter.
    
    Args:
        report_directory: Directory for report files.
        
    Returns:
        Configured CSVReporter instance.
    """
    return CSVReporter(report_directory)