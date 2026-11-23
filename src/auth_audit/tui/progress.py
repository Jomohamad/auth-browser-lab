# Signed by JOE
"""Runtime progress Terminal User Interface (Textual).

Styled like the settings TUI: plain text, ``=`` / ``-`` separators,
no decorative frames. Shows per-window progress bars in a grid that fills
the terminal width, plus a Stop control. No scrolling — all windows are
visible at once.

Keyboard shortcuts
------------------
    s / S   Stop testing gracefully (finish current attempt, then stop)
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict, List, Optional

from textual import on
from textual.app import App
from textual.containers import Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Button, Static

from .base import BaseScreen, APP_TITLE, KEY_HINTS, SEP_MAJOR, SEP_MINOR, separator


class ProgressScreen(BaseScreen):
    """Single-screen progress TUI styled like the settings pages.

    Layout (fixed height, no scrolling):

        ============================================================
        AUTH BROWSER LAB — Test Progress
        Testing N entries across M window(s).
        Per-window progress:
        Window 01: [████░░░░░░░░░░░░]  25.0% (100/400) | AUTHENTICATION_FAILED (500ms)
        Window 02: [████████░░░░░░░░]  50.0% (200/400) | AUTHENTICATION_FAILED (600ms)
        ... (more windows flow into columns based on terminal width)
        ============================================================
                                                          [S] Stop
        ============================================================
    """

    def __init__(
        self,
        app_ref: "ProgressApp",
        total_entries: int,
        num_windows: int,
        on_stop: Callable[[], None],
    ) -> None:
        super().__init__(app_ref)
        self.total_entries = total_entries
        self.num_windows = num_windows
        self._on_stop = on_stop
        self._started_at = time.monotonic()

        # Per-window progress state (updated from the test thread).
        self._window_progress: Dict[int, Dict] = {}
        for w in range(num_windows):
            count = len(range(w, total_entries, num_windows))
            self._window_progress[w] = {
                "completed": 0,
                "total": count,
                "last_result": "starting…",
                "last_ms": 0,
            }

        # Direct widget references (set during compose).
        self._window_widgets: Dict[int, Static] = {}

        self._stopped: bool = False
        self._lock = threading.Lock()
        self._summary_text = "Waiting for the run to finish."

    # -- page metadata ------------------------------------------------------
    def page_title(self) -> str:
        return "Test Progress"

    def page_subtitle(self) -> str:
        return (
            f"Testing {self.total_entries} entr"
            f"{'y' if self.total_entries == 1 else 'ies'} "
            f"across {self.num_windows} window(s)."
        )

    def _footer_text(self) -> str:
        return separator(SEP_MAJOR, self._sep_width)

    def _redraw_chrome(self) -> None:
        super()._redraw_chrome()

    # -- body ---------------------------------------------------------------
    def compose(self):
        yield Static(self._header_text(), id="header")
        yield Static(self._subtitle_text(), id="subtitle")
        yield Static("Per-window progress:", id="progress-intro")
        yield Static("", id="progress-grid")
        yield Static("Estimated remaining: Calculating…", id="eta")
        yield Static("Final report:\n" + self._summary_text, id="summary")
        yield Static(separator(SEP_MINOR, self._sep_width), id="actions-separator")
        with Vertical(id="action-bar"):
            yield Button("[S] Stop", id="stop", variant="error")
        yield Static(separator(SEP_MAJOR, self._sep_width), id="footer")

    def on_mount(self) -> None:
        super().on_mount()
        self._build_grid()

    def on_resize(self) -> None:
        super().on_resize()
        self._build_grid()

    def _build_grid(self) -> None:
        """Rebuild the progress grid as rows × columns based on terminal width.

        Each cell is one Static widget. Columns wrap so that as many
        windows fit side-by-side as the terminal allows.
        """
        # Determine columns: each progress line is ~62 chars + gutter.
        columns = max(1, min(self.num_windows, self.size.width // 66))
        rows = (self.num_windows + columns - 1) // columns

        lines: List[str] = []
        for r in range(rows):
            row_cells: List[str] = []
            for c in range(columns):
                w = r * columns + c
                if w >= self.num_windows:
                    row_cells.append("")
                else:
                    row_cells.append(self._render_window(w))
            lines.append("  ".join(row_cells).rstrip())

        grid_text = "\n".join(lines)
        try:
            widget = self.query_one("#progress-grid", Static)
            widget.update(grid_text)
        except Exception:  # noqa: BLE001 - widget may not be mounted yet
            pass

        # Store direct references for incremental updates.
        self._window_widgets = {}
        for w in range(self.num_windows):
            r = w // columns
            c = w % columns
            self._window_widgets[w] = (r, c)

    # -- rendering ----------------------------------------------------------
    @staticmethod
    def _progress_bar(completed: int, total: int, width: int = 18) -> str:
        pct = (completed / total * 100) if total > 0 else 0
        filled = int(width * pct / 100)
        return "█" * filled + "░" * (width - filled)

    def _render_window(self, window_idx: int) -> str:
        prog = self._window_progress[window_idx]
        pct = (prog["completed"] / prog["total"] * 100) if prog["total"] > 0 else 0
        bar = self._progress_bar(prog["completed"], prog["total"])
        return (
            f"Window {window_idx + 1:02d}: [{bar}] "
            f"{pct:5.1f}% ({prog['completed']}/{prog['total']}) "
            f"| {prog['last_result']} ({prog['last_ms']}ms)"
        )

    def _refresh_display(self) -> None:
        """Rebuild the whole grid so all windows update together."""
        self._build_grid()
        self._refresh_eta()

    def _refresh_eta(self) -> None:
        with self._lock:
            completed = sum(
                p["completed"] for p in self._window_progress.values()
            )
            planned = sum(
                p["total"] for p in self._window_progress.values()
            )
        if completed <= 0:
            estimate = "Calculating…"
        else:
            remaining = max(0, planned - completed)
            elapsed = max(time.monotonic() - self._started_at, 0.001)
            seconds_left = int(remaining * elapsed / completed)
            hours, remainder = divmod(seconds_left, 3600)
            minutes, seconds = divmod(remainder, 60)
            estimate = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        try:
            self.query_one("#eta", Static).update(
                f"Estimated remaining: {estimate}"
            )
        except Exception:  # noqa: BLE001 - widget may not be mounted yet
            pass

    def set_results(self, results) -> None:
        """Display a sanitized count-only final summary."""
        from collections import Counter

        counts = Counter(
            result.classification.result.value for result in results
        )
        lines = [f"Processed: {len(results)} / {self.total_entries}"]
        lines.extend(
            f"{name}: {count}" for name, count in sorted(counts.items())
        )
        self._summary_text = "\n".join(lines) if counts else "No results were produced."
        try:
            self.query_one("#summary", Static).update(
                "Final report:\n" + self._summary_text
            )
        except Exception:  # noqa: BLE001
            pass

    def set_status(self, message: str) -> None:
        """Show a status message."""
        try:
            self.query_one("#status", Static).update(message)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ #
    # Public API (called from the test thread)
    # ------------------------------------------------------------------ #
    def update_progress(
        self,
        window_idx: int,
        completed: int,
        total: int,
        result_str: str,
        ms: int,
    ) -> None:
        """Called by the test worker after each entry."""
        if not 0 <= window_idx < self.num_windows:
            return
        total = max(0, total)
        completed = min(max(0, completed), total) if total else 0
        with self._lock:
            self._window_progress[window_idx] = {
                "completed": completed,
                "total": total,
                "last_result": result_str,
                "last_ms": ms,
            }
        self._refresh_display()

    def is_stopped(self) -> bool:
        with self._lock:
            return self._stopped

    # -- keyboard ----------------------------------------------------------
    def on_key(self, event) -> None:  # textual.events.Key
        key = event.key.lower()
        if key == "s":
            event.stop()
            self.action_stop()
        super().on_key(event)

    # -- actions ------------------------------------------------------------
    def action_stop(self) -> None:
        """Stop testing gracefully."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        self.set_status("Stop requested — finishing current attempt…")
        try:
            self._on_stop()
        except Exception:  # noqa: BLE001
            pass

    @on(Button.Pressed, "#stop")
    def _stop_pressed(self) -> None:
        self.action_stop()


class ProgressApp(App):
    """Textual app wrapper that hosts ProgressScreen."""

    def __init__(
        self,
        total_entries: int,
        num_windows: int,
        on_stop: Callable[[], None],
        on_ready: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__()
        self.total_entries = total_entries
        self.num_windows = num_windows
        self._on_stop = on_stop
        self._on_ready = on_ready
        self.screen_instance: Optional[ProgressScreen] = None

    # -- forwarding methods for the test thread ----------------------------
    def update_progress(
        self,
        window_idx: int,
        completed: int,
        total: int,
        result_str: str,
        ms: int,
    ) -> None:
        """Forward progress updates to the screen (thread-safe)."""
        if self.screen_instance is not None and self.is_running:
            self.call_from_thread(
                self.screen_instance.update_progress,
                window_idx, completed, total, result_str, ms,
            )

    def set_status(self, message: str) -> None:
        """Forward status messages to the screen (thread-safe)."""
        if self.screen_instance is not None and self.is_running:
            self.call_from_thread(self.screen_instance.set_status, message)

    def set_results(self, results) -> None:
        """Forward the final result summary to the mounted screen."""
        if self.screen_instance is not None and self.is_running:
            self.call_from_thread(self.screen_instance.set_results, results)

    def on_mount(self) -> None:
        self.screen_instance = ProgressScreen(
            self, self.total_entries, self.num_windows,
            self._on_stop,
        )
        self.install_screen(self.screen_instance, name="progress")
        self.push_screen("progress")
        if self._on_ready is not None:
            self.call_after_refresh(self._on_ready)
