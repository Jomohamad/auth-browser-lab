# Signed by JOE
"""Browser automation for authentication testing.

This module handles the Playwright browser automation workflow
for authorized authentication testing.

Supports concurrent browser windows, resume-on-stop, and selective
reporting (only confirmed successes are written to the CSV report).
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Callable, List, Optional
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
    window_index: int = 0


# Type for progress callback: (window_idx, completed, total, result_str, ms) -> None
ProgressCallback = Callable[[int, int, int, str, int], None]


class ResumeState:
    """Tracks resume state for stopping and resuming test runs.

    Persists the last completed entry index so the next run can continue
    from the following entry after a stop (Ctrl+C or security challenge).
    """

    def __init__(self, state_file: str, enabled: bool = True):
        self.state_file = Path(state_file)
        self.enabled = enabled
        self.last_completed_index: int = -1
        self.password_file: str = ""
        self.target_url: str = ""
        self._lock = Lock()

    def load(self) -> int:
        """Load resume state. Returns the last completed index, or -1."""
        if not self.enabled or not self.state_file.exists():
            return -1
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.last_completed_index = data.get("last_completed_index", -1)
            self.password_file = data.get("password_file", "")
            self.target_url = data.get("target_url", "")
            return self.last_completed_index
        except Exception:
            return -1

    def save(self, last_completed_index: int, password_file: str,
             target_url: str) -> None:
        """Save resume state (best-effort, never raises)."""
        if not self.enabled:
            return
        with self._lock:
            self.last_completed_index = last_completed_index
            self.password_file = password_file
            self.target_url = target_url
            try:
                self.state_file.parent.mkdir(parents=True, exist_ok=True)
                data = {
                    "last_completed_index": last_completed_index,
                    "password_file": password_file,
                    "target_url": target_url,
                    "timestamp": time.time(),
                }
                self.state_file.write_text(
                    json.dumps(data, indent=2), encoding="utf-8"
                )
            except Exception:
                pass

    def clear(self) -> None:
        """Clear resume state after a complete or successful run."""
        if self.enabled and self.state_file.exists():
            try:
                self.state_file.unlink()
            except Exception:
                pass


class AuthTester:
    """Main authentication testing orchestrator."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.classifier = ResultClassifier(config.auth)
        self.detector = SecurityChallengeDetector(config.security)
        self.reporter = CSVReporter(config.report.report_directory)

        # Cross-attempt control flags (thread-safe reads/writes of bools).
        self._stop_requested: bool = False

        # Pre-compute allowed hosts set for fast lookup.
        self._allowed_hosts = set(config.allowed_hosts)

        # Resume state.
        self.resume_state = ResumeState(
            config.resume_state_file,
            enabled=config.resume_enabled,
        )

    # ------------------------------------------------------------------ #
    # Safety helpers
    # ------------------------------------------------------------------ #
    def _check_host_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            return hostname in self._allowed_hosts
        except Exception:
            return False

    def _navigated_off_login(self, current_url: str) -> bool:
        try:
            login_path = urlparse(self.config.target_url).path
            current_path = urlparse(current_url).path
            return current_path != login_path
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #
    def run(self, passwords: PasswordFileResult, resume_from: int = -1,
            progress_callback: Optional[ProgressCallback] = None,
            ui_mode: bool = False) -> List[TestRunResult]:
        """Run authentication tests with concurrent windows and resume.

        When ``concurrent_windows`` is 1, entries are processed
        sequentially on a single page (backward compatible).  When greater
        than 1, entries are distributed round-robin across that many
        persistent browser windows via a thread pool.

        After each attempt the page returns to the login URL (via
        ``reload`` / ``goto``) to avoid ``ERR_ABORTED`` from rapid
        same-URL navigations.

        Only ``SUCCESS_CONFIRMED`` results are written to the CSV report.

        Args:
            passwords: Validated password file result.
            resume_from: Index to resume from (-1 = start fresh).
            progress_callback: Optional callback called after each entry:
                (window_idx, completed, total, result_str, ms).
            ui_mode: When True, runs under a TUI (suppresses console prints).

        Returns:
            List of test run results (one per processed entry).
        """
        results = []
        total = passwords.count

        # Determine starting index.
        start_index = 0
        if resume_from >= 0:
            start_index = resume_from + 1
        elif self.resume_state.enabled:
            saved = self.resume_state.load()
            # Only resume if the saved state matches this run's target and
            # password file; otherwise start fresh (avoids stale state between
            # unrelated runs).
            if saved >= 0 and (
                self.resume_state.password_file == passwords.source_path
                and self.resume_state.target_url == self.config.target_url
            ):
                start_index = saved + 1
            else:
                start_index = 0

        if start_index > 0 and not ui_mode:
            print(f"\n[RESUME] Resuming from entry {start_index + 1}/{total}")

        remaining_passwords = passwords.passwords[start_index:]
        remaining_indices = list(range(start_index, total))

        if not remaining_passwords:
            if not ui_mode:
                print("\nNo remaining entries to process.")
            return results

        num_windows = min(
            self.config.browser.concurrent_windows, len(remaining_passwords)
        )
        if num_windows < 1:
            num_windows = 1

        if not ui_mode:
            print(
                f"\nLoaded {total} password entr{'y' if total == 1 else 'ies'} "
                f"from {passwords.source_path}. "
                f"Concurrent windows: {num_windows}. "
                f"Starting from entry {start_index + 1}."
            )

        # ------------------------------------------------------------------
        # Progress tracking (per-window progress bars updated in place)
        # ------------------------------------------------------------------
        import sys as _sys

        progress_lock = Lock()

        def _progress_bar(completed: int, total: int, width: int = 24) -> str:
            pct = (completed / total * 100) if total > 0 else 0
            filled = int(width * pct / 100)
            return "█" * filled + "░" * (width - filled)

        def _render_window(window_idx: int, completed: int, total: int,
                           last_result: str, last_ms: int) -> str:
            pct = (completed / total * 100) if total > 0 else 0
            bar = _progress_bar(completed, total)
            return (
                f"Window {window_idx + 1}: [{bar}] "
                f"{pct:5.1f}% ({completed}/{total}) "
                f"| {last_result} ({last_ms}ms)"
            )

        def _render_all_windows() -> None:
            """Rewrite all window progress bars in place using ANSI codes."""
            lines = []
            for w in range(num_windows):
                prog = window_progress[w]
                lines.append(_render_window(
                    w, prog["completed"], prog["total"],
                    prog["last_result"], prog["last_ms"],
                ))
            # Move cursor up to the first bar line, then overwrite every line.
            _sys.stdout.write(f"\033[{num_windows}A")
            for i, line in enumerate(lines):
                if i > 0:
                    _sys.stdout.write("\n")
                # \r = return to line start, \033[K = clear to end of line
                _sys.stdout.write(f"\r\033[K{line}")
            _sys.stdout.flush()

        # Per-window progress state
        window_progress: dict = {}
        entries_per_window = []
        for w in range(num_windows):
            count = len(range(w, len(remaining_passwords), num_windows))
            entries_per_window.append(count)
            window_progress[w] = {
                "completed": 0,
                "total": count,
                "last_result": "starting…",
                "last_ms": 0,
            }

        # Print initial progress bars (one line per window)
        for w in range(num_windows):
            prog = window_progress[w]
            print(_render_window(
                w, 0, prog["total"], prog["last_result"], prog["last_ms"]
            ))
        print()  # space below the initial bars

        # ------------------------------------------------------------------
        # Sequential path (concurrent_windows == 1): single page, one entry
        # at a time.  Backward compatible with tests that mock
        # _run_single_test directly.
        # ------------------------------------------------------------------
        if num_windows == 1:
            with sync_playwright() as p:
                browser = self._launch_browser(p)
                context = browser.new_context(
                    **browser_helpers.build_context_options(
                        self.config.browser.viewport_width,
                        self.config.browser.viewport_height,
                    )
                )
                page = context.new_page()
                try:
                    for i, (pwd_idx, pwd) in enumerate(
                            zip(remaining_indices, remaining_passwords)
                    ):
                        if self._stop_requested:
                            print(
                                f"\n[STOP] Safety stop in effect. "
                                f"Skipping remaining "
                                f"{total - (start_index + i)} entr"
                                f"{'y' if total - (start_index + i) == 1 else 'ies'}."
                            )
                            break

                        attempt_number = pwd_idx + 1

                        result = self._run_single_test(
                            page, pwd, attempt_number, total
                        )
                        result.window_index = 0
                        results.append(result)

                        # Save resume progress after every entry.
                        self.resume_state.save(
                            pwd_idx, passwords.source_path,
                            self.config.target_url,
                        )

                        state = result.classification.result
                        prog = window_progress[0]
                        prog["completed"] += 1
                        prog["last_result"] = state.value
                        prog["last_ms"] = result.elapsed_time_ms
                        with progress_lock:
                            if progress_callback and not ui_mode:
                                progress_callback(
                                    0, prog["completed"], prog["total"],
                                    prog["last_result"], prog["last_ms"]
                                )
                            else:
                                _render_all_windows()

                        if state == AuthenticationResult.SUCCESS_CONFIRMED:
                            self._stop_requested = True
                            if not ui_mode:
                                self._print_stop_block(
                                    state.value, attempt_number,
                                    total - attempt_number,
                                    "AUTHENTICATION_SUCCESS",
                                    matched_value=pwd,
                                )
                            break

                        if (self.config.stop_on_security_challenge
                                and result.security_challenge
                                and result.security_challenge.detected):
                            self._stop_requested = True
                            if not ui_mode:
                                self._print_stop_block(
                                    state.value, attempt_number,
                                    total - attempt_number,
                                    "SECURITY_CHALLENGE",
                                )
                            break
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass
                    try:
                        context.close()
                    except Exception:
                        pass
                    browser.close()

            # Final progress for sequential mode
            with progress_lock:
                if progress_callback and not ui_mode:
                    progress_callback(
                        0, prog["completed"], prog["total"],
                        prog["last_result"], prog["last_ms"]
                    )
                else:
                    _render_all_windows()
            print()

        # ------------------------------------------------------------------
        # Concurrent path (concurrent_windows > 1): round-robin across
        # persistent browser windows via a thread pool.
        # ------------------------------------------------------------------
        else:
            num_windows = min(num_windows, 20)
            results_map: dict = {}
            stop_flag = {"stopped": False}
            results_lock = Lock()
            winning_window = {"idx": None}

            def worker(window_idx: int) -> None:
                """Each worker owns its own Playwright browser/page (thread-safe).

                Guarantees:
                  * One sync_playwright() instance per window (isolated event loop).
                  * Each password is tried at most once per window (tried set).
                  * Windows run in parallel via ThreadPoolExecutor.
                """
                with sync_playwright() as p:
                    browser = self._launch_browser(p)
                    context = browser.new_context(
                        **browser_helpers.build_context_options(
                            self.config.browser.viewport_width,
                            self.config.browser.viewport_height,
                        )
                    )
                    page = context.new_page()
                    observed = {"http_status": None, "challenge": None}
                    # Per-window set: never try the same password twice in one window.
                    tried_passwords: set = set()

                    def on_response(response: Response) -> None:
                        request_url = response.url.lower()
                        auth_keywords = (
                            "login", "auth", "session", "callback",
                            "signin", "sign-in",
                        )
                        if any(k in request_url for k in auth_keywords):
                            observed["http_status"] = response.status
                            challenge = self.detector.check_response(response)
                            if challenge and challenge.detected:
                                observed["challenge"] = challenge

                    page.on("response", on_response)

                    try:
                        # Round-robin: window N takes entries N, N+W, N+2W, ...
                        # so every password goes to exactly one window.
                        for pos in range(
                            window_idx, len(remaining_passwords), num_windows
                        ):
                            if stop_flag["stopped"] or self._stop_requested:
                                stop_flag["stopped"] = True
                                break

                            pwd_idx = remaining_indices[pos]
                            pwd = remaining_passwords[pos]

                            # Skip if this window already tried this password
                            # (defense in depth; round-robin already prevents it).
                            if pwd in tried_passwords:
                                continue
                            tried_passwords.add(pwd)

                            attempt_number = pwd_idx + 1

                            result = self._run_single_test(
                                page, pwd, attempt_number, total, observed
                            )

                            with results_lock:
                                results_map[pwd_idx] = result
                                result.window_index = window_idx
                                self.resume_state.save(
                                    pwd_idx, passwords.source_path,
                                    self.config.target_url,
                                )

                            state = result.classification.result
                            prog = window_progress[window_idx]
                            prog["completed"] += 1
                            prog["last_result"] = state.value
                            prog["last_ms"] = result.elapsed_time_ms
                            with progress_lock:
                                if progress_callback and not ui_mode:
                                    progress_callback(
                                        window_idx, prog["completed"],
                                        prog["total"], prog["last_result"],
                                        prog["last_ms"]
                                    )
                                else:
                                    _render_all_windows()

                            if state == AuthenticationResult.SUCCESS_CONFIRMED:
                                winning_window["idx"] = window_idx
                                stop_flag["stopped"] = True
                                self._stop_requested = True
                                if not ui_mode:
                                    self._print_stop_block(
                                        state.value, attempt_number,
                                        total - attempt_number,
                                        "AUTHENTICATION_SUCCESS",
                                        matched_value=pwd,
                                    )
                                break

                            if (self.config.stop_on_security_challenge
                                    and result.security_challenge
                                    and result.security_challenge.detected):
                                stop_flag["stopped"] = True
                                self._stop_requested = True
                                if not ui_mode:
                                    self._print_stop_block(
                                        state.value, attempt_number,
                                        total - attempt_number,
                                        "SECURITY_CHALLENGE",
                                    )
                                break
                    finally:
                        try:
                            page.remove_listener("response", on_response)
                        except Exception:
                            pass
                        try:
                            page.close()
                        except Exception:
                            pass
                        try:
                            context.close()
                        except Exception:
                            pass
                        try:
                            browser.close()
                        except Exception:
                            pass

            with ThreadPoolExecutor(max_workers=num_windows) as executor:
                futures = [
                    executor.submit(worker, w) for w in range(num_windows)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass  # Suppress errors during shutdown

            # Print final progress bars (one line per window)
            print()
            with progress_lock:
                if progress_callback and not ui_mode:
                    for w in range(num_windows):
                        prog = window_progress[w]
                        progress_callback(
                            w, prog["completed"], prog["total"],
                            prog["last_result"], prog["last_ms"]
                        )
                else:
                    _render_all_windows()
            print()

            for i in range(start_index, total):
                if i in results_map:
                    results.append(results_map[i])

        # Write report: ONLY confirmed successes (secret-free by default).
        for result in results:
            if result.classification.result == AuthenticationResult.SUCCESS_CONFIRMED:
                self._write_report(result, passwords, result.password_index + 1)

        # Clear resume state if we ran to completion or found success.
        if (not self._stop_requested
                or any(r.classification.result == AuthenticationResult.SUCCESS_CONFIRMED
                       for r in results)):
            self.resume_state.clear()

        return results

    def _on_response(self, page: Page, response: Response,
                     observed: dict) -> None:
        """Track HTTP responses for a single page (thread-safe via observed dict)."""
        request_url = response.url.lower()
        auth_keywords = (
            "login", "auth", "session", "callback", "signin", "sign-in",
        )
        if any(k in request_url for k in auth_keywords):
            observed["http_status"] = response.status
            challenge = self.detector.check_response(response)
            if challenge and challenge.detected:
                observed["challenge"] = challenge

    # ------------------------------------------------------------------ #
    # Single test (thread-safe: all state is local)
    # ------------------------------------------------------------------ #
    def _run_single_test(self,
                         page: Page,
                         password: str,
                         attempt_number: int,
                         total_entries: int = 1,
                         observed: Optional[dict] = None) -> TestRunResult:
        """Run a single authentication test attempt.

        All state is local to this call (no ``self._`` per-attempt fields)
        so the method is safe to call concurrently from multiple threads.
        """
        start_time = time.perf_counter()
        navigation_error = False
        error_message = ""

        # Local per-attempt state.
        login_page_status: Optional[int] = None
        auth_response_status: Optional[int] = None
        security_challenge_detected: Optional[SecurityChallengeResult] = None
        redirect_chain: List[str] = []
        page_title = ""
        form_detected = False
        selector_diagnostic = ""

        if observed is None:
            observed = {"http_status": None, "challenge": None}

        response = None

        try:
            # 1. Navigate to login page.
            # Use reload when already on the target to avoid
            # ERR_ABORTED from rapid same-URL goto calls.
            try:
                current_url = page.url
                if current_url == self.config.target_url:
                    page.reload(wait_until="domcontentloaded")
                else:
                    response = page.goto(
                        self.config.target_url,
                        wait_until="domcontentloaded",
                        timeout=self.config.browser.navigation_timeout_ms,
                    )
            except Exception:
                response = page.goto(
                    self.config.target_url,
                    wait_until="domcontentloaded",
                    timeout=self.config.browser.navigation_timeout_ms,
                )

            if response:
                login_page_status = response.status

            # If login page itself returns 404, stop immediately.
            if login_page_status == 404:
                elapsed = int((time.perf_counter() - start_time) * 1000)
                try:
                    page_title = page.title()
                except Exception:
                    pass
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.LOGIN_PAGE_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=(
                            "Login page returned HTTP 404 (main document)"
                        ),
                    ),
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=False,
                    selector_diagnostic="Login page not found (404)",
                    navigation_error=True,
                    error_message="Login page returned HTTP 404",
                )

            # Get page title.
            try:
                page_title = page.title()
            except Exception:
                pass

            # 2. Validate and fill username field.
            selector_diag = self._wait_for_selector_with_diagnostics(
                page,
                self.config.auth.username_selector,
                "username",
                self.config.browser.navigation_timeout_ms,
            )
            if selector_diag:
                self._selector_diagnostic = selector_diag
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.SELECTOR_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=(
                            f"Username selector issue: {selector_diag}"
                        ),
                    ),
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=False,
                    selector_diagnostic=selector_diag,
                    navigation_error=True,
                    error_message=f"Username selector not found: {selector_diag}",
                )

            page.locator(self.config.auth.username_selector).fill(
                self.config.auth.username
            )

            # 3. Validate and fill password field.
            selector_diag = self._wait_for_selector_with_diagnostics(
                page,
                self.config.auth.password_selector,
                "password",
                self.config.browser.navigation_timeout_ms,
            )
            if selector_diag:
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.SELECTOR_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=f"Password selector issue: {selector_diag}",
                    ),
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=False,
                    selector_diagnostic=selector_diag,
                    navigation_error=True,
                    error_message=f"Password selector not found: {selector_diag}",
                )

            page.locator(self.config.auth.password_selector).fill(password)

            # 4. Validate submit selector.
            selector_diag = self._wait_for_selector_with_diagnostics(
                page,
                self.config.auth.submit_selector,
                "submit",
                self.config.browser.navigation_timeout_ms,
            )
            if selector_diag:
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.SELECTOR_NOT_FOUND,
                        confidence="high",
                        diagnostic_summary=f"Submit selector issue: {selector_diag}",
                    ),
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=False,
                    selector_diagnostic=selector_diag,
                    navigation_error=True,
                    error_message=f"Submit selector not found: {selector_diag}",
                )

            form_detected = True

            # 5. Configurable delay before submit (kept minimal for speed).
            delay = self.config.browser.delay_before_submit_seconds
            if delay > 0:
                time.sleep(delay)

            # 6. Check for pre-existing security challenges.
            challenge = self.detector.check_page_content(page)
            if challenge and challenge.detected:
                security_challenge_detected = challenge
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.STOPPED_SECURITY_CHALLENGE,
                        confidence="high",
                        diagnostic_summary=challenge.diagnostic_summary,
                    ),
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=challenge,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=form_detected,
                    selector_diagnostic="",
                    navigation_error=False,
                    error_message="",
                )

            # 6a. Verify the origin is still allowlisted before submitting.
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
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=form_detected,
                    selector_diagnostic="",
                    navigation_error=True,
                    error_message="Non-local origin before submit",
                )

            page.locator(self.config.auth.submit_selector).click()

            # 8. Wait for navigation/response (short timeout for speed).
            try:
                page.wait_for_load_state(
                    "domcontentloaded", timeout=3000
                )
            except Exception:
                pass

            # Brief wait for dynamic content (kept under 500ms total).
            page.wait_for_timeout(300)

            # Update page title after navigation.
            try:
                page_title = page.title()
            except Exception:
                pass

            # Check if navigation went to an unauthorized host.
            if not self._check_host_allowed(page.url):
                elapsed = int((time.perf_counter() - start_time) * 1000)
                return TestRunResult(
                    password_index=attempt_number - 1,
                    classification=ClassificationResult(
                        result=AuthenticationResult.UNAUTHORIZED_HOST_BLOCKED,
                        confidence="high",
                        diagnostic_summary=f"Navigation to unauthorized host: {page.url}",
                    ),
                    http_status=observed["http_status"],
                    login_page_status=login_page_status,
                    auth_response_status=None,
                    security_challenge=None,
                    elapsed_time_ms=elapsed,
                    final_page_url=page.url,
                    page_title=page_title,
                    redirect_chain=redirect_chain,
                    form_detected=form_detected,
                    selector_diagnostic="",
                    navigation_error=True,
                    error_message=f"Navigation to unauthorized host: {page.url}",
                )

            # 9. Check for security challenges after submit.
            challenge = self.detector.check_page_content(page)
            if challenge and challenge.detected:
                security_challenge_detected = challenge

            nav_challenge = self.detector.check_navigation(page)
            if nav_challenge and nav_challenge.detected:
                security_challenge_detected = nav_challenge

            elapsed = int((time.perf_counter() - start_time) * 1000)

            # Determine whether the browser navigated off the login page.
            navigated_away = self._navigated_off_login(page.url)

            # 10. Classify the result.
            classification = self.classifier.classify(
                page=page,
                http_status=observed["http_status"],
                security_challenge=(
                    security_challenge_detected.challenge_type
                    if security_challenge_detected else None
                ),
                navigation_error=navigation_error,
                login_page_status=login_page_status,
                selector_diagnostic=selector_diagnostic,
                form_ready=form_detected,
                navigated_away=navigated_away,
            )

            return TestRunResult(
                password_index=attempt_number - 1,
                classification=classification,
                http_status=observed["http_status"],
                login_page_status=login_page_status,
                auth_response_status=auth_response_status,
                security_challenge=security_challenge_detected,
                elapsed_time_ms=elapsed,
                final_page_url=page.url,
                page_title=page_title,
                redirect_chain=redirect_chain,
                form_detected=form_detected,
                selector_diagnostic=selector_diagnostic,
                navigation_error=navigation_error,
                error_message=error_message,
            )

        except Exception as e:
            elapsed = int((time.perf_counter() - start_time) * 1000)
            navigation_error = True
            error_message = f"{type(e).__name__}: {str(e)[:200]}"

            if "Timeout" in str(e) and "wait_for" in str(e):
                selector_diag = self._extract_selector_from_error(str(e))
                selector_diagnostic = selector_diag
                classification = ClassificationResult(
                    result=AuthenticationResult.SELECTOR_NOT_FOUND,
                    confidence="high",
                    diagnostic_summary=f"Selector timeout: {selector_diag}",
                )
            else:
                classification = ClassificationResult(
                    result=AuthenticationResult.NAVIGATION_ERROR,
                    confidence="high",
                    diagnostic_summary=error_message,
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
                http_status=observed["http_status"],
                login_page_status=login_page_status,
                auth_response_status=auth_response_status,
                security_challenge=security_challenge_detected,
                elapsed_time_ms=elapsed,
                final_page_url=final_url,
                page_title=page_title,
                redirect_chain=redirect_chain,
                form_detected=form_detected,
                selector_diagnostic=selector_diagnostic,
                navigation_error=navigation_error,
                error_message=error_message,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _print_stop_block(
        self, result_label: str, entry_number: int, remaining: int,
        stop_reason: str, matched_value: Optional[str] = None,
    ) -> None:
        """Print a standardized stop summary for terminal output."""
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
        return browser_helpers.launch_browser(
            playwright,
            browser=self.config.browser.browser.value,
            headless=self.config.browser.headless,
        )

    def _wait_for_selector_with_diagnostics(
        self,
        page: Page,
        selector: str,
        field_name: str,
        timeout: int,
    ) -> Optional[str]:
        return browser_helpers.wait_for_selector_with_diagnostics(
            page, selector, field_name, timeout
        )

    def _extract_selector_from_error(self, error: str) -> str:
        import re
        match = re.search(r'locator\("([^"]+)"\)', error)
        if match:
            return f"Timeout waiting for '{match.group(1)}'"
        match = re.search(r"locator\('([^']+)'\)", error)
        if match:
            return f"Timeout waiting for '{match.group(1)}'"
        return f"Selector timeout: {error[:150]}"

    def _write_report(
        self,
        result: TestRunResult,
        passwords: PasswordFileResult,
        attempt_number: int,
    ):
        """Write test result to CSV report (only called for successes)."""
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
            window_index=result.window_index,
        )

        report_path = self.reporter.write_record(record)
        print(
            f"[Window {result.window_index + 1} "
            f"Entry {attempt_number}/{passwords.count}] "
            f"Report written to: {report_path}"
        )

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
    resume_from: int = -1,
    progress_callback: Optional[ProgressCallback] = None,
    ui_mode: bool = False,
) -> List[TestRunResult]:
    """Run the authentication test sequence.

    Reads the entire password file (or uses a single provided credential)
    and processes entries concurrently across multiple browser windows.

    Args:
        config: Application configuration.
        override_password: Optional single credential supplied at run time.
        resume_from: Index to resume from (-1 = start fresh / use saved state).
        progress_callback: Optional callback called after each entry:
            (window_idx, completed, total, result_str, ms).
        ui_mode: When True, runs under a TUI (suppresses console prints).

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
        if not ui_mode:
            print("Validating password file...")
        passwords = read_password_file(config.password_file)
        if not ui_mode:
            print(
                f"Password file valid: {passwords.count} entr"
                f"{'y' if passwords.count == 1 else 'ies'} loaded from "
                f"{passwords.source_path}"
            )

    tester = AuthTester(config)
    results = tester.run(
        passwords, resume_from=resume_from,
        progress_callback=progress_callback, ui_mode=ui_mode,
    )

    return results