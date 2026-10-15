# Signed by JOE
"""CSV reporting for authentication test results.

This module handles writing sanitized test results to CSV files
without storing any sensitive information.
"""

import csv
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .result_classifier import AuthenticationResult


@dataclass
class TestReportRecord:
    """Sanitized test report record for CSV output.

    Deliberately excludes passwords, hashes, cookies, tokens, authorization
    headers, request bodies, full page HTML and full URLs (query/fragment).
    """
    timestamp_utc: str
    target_host: str
    authentication_provider: str
    attempt_number: int
    total_entries: int
    result: str
    http_status: Optional[int]
    login_page_status: Optional[int]
    auth_response_status: Optional[int]
    security_challenge_detected: bool
    elapsed_time_ms: int
    final_page_path: str
    page_title: str
    form_detected: bool
    selector_diagnostic: str
    diagnostic_summary: str
    candidate_password: str = ""


class CSVReporter:
    """Handles writing sanitized test results to a consolidated CSV report."""

    # Columns written to the CSV (kept backward-compatible where practical).
    FIELDNAMES = [
        "timestamp_utc",
        "attempt_number",
        "total_entries",
        "result",
        "http_status",
        "security_challenge_detected",
        "elapsed_time_ms",
        "diagnostic_summary",
        # Additional sanitized diagnostics:
        "target_host",
        "authentication_provider",
        "login_page_status",
        "auth_response_status",
        "final_page_path",
        "page_title",
        "form_detected",
        "selector_diagnostic",
        # Opt-in plaintext candidate password (empty unless the operator
        # enables include_password_in_report for their own local report).
        "candidate_password",
    ]

    def __init__(self, report_directory: str):
        self.report_directory = Path(report_directory)
        self.report_directory.mkdir(parents=True, exist_ok=True)

    def write_record(self, record: TestReportRecord) -> Path:
        """Write a single test record to the consolidated CSV report."""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        report_file = self.report_directory / f"auth-test-{date_str}.csv"

        file_exists = report_file.exists()
        is_empty = file_exists and report_file.stat().st_size == 0

        with report_file.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)

            if not file_exists or is_empty:
                writer.writeheader()

            writer.writerow(asdict(record))

        return report_file

    def create_record(
        self,
        target_url: str,
        auth_provider: str,
        attempt_number: int,
        total_entries: int,
        result: AuthenticationResult,
        http_status: Optional[int],
        login_page_status: Optional[int],
        auth_response_status: Optional[int],
        security_challenge_detected: bool,
        elapsed_time_ms: int,
        final_page_url: str,
        page_title: str,
        form_detected: bool,
        selector_diagnostic: str,
        diagnostic_summary: str,
        secrets: Optional[List[str]] = None,
        candidate_password: Optional[str] = None,
        include_password_in_report: bool = False,
    ) -> TestReportRecord:
        """Create a sanitized test report record.

        ``secrets`` (the full candidate password list) is redacted verbatim
        from every free-text field, so no password can leak while useful
        diagnostic text is preserved. Query strings/URL fragments are also
        stripped before storage.

        If ``include_password_in_report`` is True (operator opt-in for their
        own local/gitignored report), the exact ``candidate_password`` is
        written to the dedicated ``candidate_password`` column.
        """
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        target_host = parsed.hostname or "unknown"

        # Store only scheme://host/path (strip query string and fragment).
        final_parsed = urlparse(final_page_url)
        final_page_path = f"{final_parsed.scheme}://{final_parsed.netloc}{final_parsed.path or '/'}"

        return TestReportRecord(
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            target_host=target_host,
            authentication_provider=auth_provider,
            attempt_number=attempt_number,
            total_entries=total_entries,
            result=result.value,
            http_status=http_status,
            login_page_status=login_page_status,
            auth_response_status=auth_response_status,
            security_challenge_detected=security_challenge_detected,
            elapsed_time_ms=elapsed_time_ms,
            final_page_path=self._sanitize_summary(final_page_path, secrets),
            page_title=self._sanitize_summary(page_title, secrets),
            form_detected=form_detected,
            selector_diagnostic=self._sanitize_summary(selector_diagnostic, secrets),
            diagnostic_summary=self._sanitize_summary(diagnostic_summary, secrets),
            candidate_password=(candidate_password or "") if include_password_in_report else "",
        )

    def _sanitize_summary(
        self, summary: str, secrets: Optional[List[str]] = None
    ) -> str:
        """Sanitize free text.

        The exact candidate password values are redacted verbatim (guaranteeing
        no password ever appears), together with token/JWT/session patterns.
        Unlike a naive length rule, this preserves useful diagnostic words.
        """
        if not summary:
            return ""

        import re

        # 1. Targeted, exhaustive redaction of the actual password values.
        for secret in secrets or []:
            if secret and secret in summary:
                summary = summary.replace(secret, "[REDACTED]")

        # 2. Long token-like strings.
        summary = re.sub(r"\b[a-zA-Z0-9]{32,}\b", "[REDACTED]", summary)
        # 3. JWT-like strings.
        summary = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", summary
        )
        # 4. Cookie/token/session key=value patterns.
        summary = re.sub(
            r"(session|token|auth|csrf|xsrf|password|passwd|pwd)[=:]\s*[^;\s]+",
            r"\1=[REDACTED]",
            summary,
            flags=re.IGNORECASE,
        )

        if len(summary) > 500:
            summary = summary[:497] + "..."

        return summary


def create_reporter(report_directory: str) -> CSVReporter:
    """Factory function to create a CSV reporter."""
    return CSVReporter(report_directory)