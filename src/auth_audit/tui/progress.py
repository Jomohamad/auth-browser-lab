# Signed by JOE
"""Runtime progress Terminal User Interface (Textual).

Styled like the settings TUI: plain text, ``=`` / ``-`` separators,
no decorative frames.  Shows per-window progress bars and Stop / Resume /
End controls with keyboard shortcuts.

Keyboard shortcuts
------------------
    s / S   Stop testing gracefully (finish current attempt, then stop)
    r / R   Resume testing after a stop
    e / E   End testing immediately (abort in-flight attempts)
    q / Q   Quit the TUI (alias for End)
"""

from __future__ import annotations

import threading
from typing import Callable, Dict, Optional

from textual.app import App

from .base import BaseScreen, APP_TITLE, KEY_HINTS, SEP_MAJOR, SEP_MINOR, separator
from .entries import ActionEntry, ListPanel, StaticEntry


class ProgressScreen(BaseScreen):
    """Single-screen progress TUI styled like the settings pages."""

    def __init__(
        self,
        app_ref: "ProgressApp",
        total_entries: int,
        num_windows: int,
        on_stop: Callable[[], None],
        on_resume: Callable[[], None],
        on_end: Callable[[], None],
    ) -> None:
        super().__init__(app_ref)
        self.total_entries = total_entries
        self.num_windows = num_windows
        self._on_stop = on_stop
        self._on_resume = on_resume
        self._on_end = on_end

        # Per-window progress state (updated from the test thread).
        self._window_progress: Dict[int, Dict] = {}
        for w in range(num_windows):
            self._window_progress[w] = {
                "completed": 0,
                "total": 0,
                "last_result": "starting…",
                "last_ms": 0,
            }

        self._stopped: bool = False
        self._ended: bool = False
        self._lock = threading.Lock()

    # -- page metadata ------------------------------------------------------
    def page_title(self) -> str:
        return "Test Progress"

    def page_subtitle(self) -> str:
        return (
            f"Testing {self.total_entries} entr"
            f"{'y' if self.total_entries == 1 else 'ies'} "
            f"across {self.num_windows} window(s)."
        )

    # -- body ---------------------------------------------------------------
    def _build_body(self):
        entries = list(self._build_body_entries()) + [
            ActionEntry("stop", "[S] Stop", can_focus=True),
            ActionEntry("resume", "[R] Resume", can_focus=True),
            ActionEntry("end", "[E] End", can_focus=True),
        ]
        return ListPanel(
            entries,
            selected_index=0,
            on_activate=self._on_entry_activated,
            on_select=self._on_entry_selected,
            id="body",
        )

    def _build_body_entries(self) -> list:
        entries: list = []
        entries.append(StaticEntry("progress-intro", "Per-window progress:"))
        for w in range(self.num_windows):
            entries.append(
                StaticEntry(f"progress-window-{w}", self._render_window(w))
            )
        return entries

    # -- rendering ----------------------------------------------------------
    @staticmethod
    def _progress_bar(completed: int, total: int, width: int = 24) -> str:
        pct = (completed / total * 100) if total > 0 else 0
        filled = int(width * pct / 100)
        return "█" * filled + "░" * (width - filled)

    def _render_window(self, window_idx: int) -> str:
        prog = self._window_progress[window_idx]
        pct = (prog["completed"] / prog["total"] * 100) if prog["total"] > 0 else 0
        bar = self._progress_bar(prog["completed"], prog["total"])
        return (
            f"Window {window_idx + 1}: [{bar}] "
            f"{pct:5.1f}% ({prog['completed']}/{prog['total']}) "
            f"| {prog['last_result']} ({prog['last_ms']}ms)"
        )

    def _refresh_display(self) -> None:
        """Redraw all window progress lines."""
        try:
            for w in range(self.num_windows):
                widget = self.query_one(f"#progress-window-{w}", StaticEntry)
                widget.set_text(self._render_window(w))
        except Exception:  # noqa: BLE001 - widget may not be mounted yet
            pass

    def set_status(self, message: str) -> None:
        """Show a status message."""
        try:
            from textual.widgets import Static

            widget = self.query_one("#status", Static)
            widget.update(message)
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
        with self._lock:
            self._window_progress[window_idx] = {
                "completed": completed,
                "total": total,
                "last_result": result_str,
                "last_ms": ms,
            }
        self.app_ref.call_from_thread(self._refresh_display)

    def is_stopped(self) -> bool:
        with self._lock:
            return self._stopped

    def is_ended(self) -> bool:
        with self._lock:
            return self._ended

    # -- keyboard ----------------------------------------------------------
    def on_key(self, event) -> None:  # textual.events.Key
        key = event.key.lower()
        if key == "s":
            event.stop()
            self.action_stop()
        elif key == "r":
            event.stop()
            self.action_resume()
        elif key in ("e", "q"):
            event.stop()
            self.action_end()
        super().on_key(event)

    # -- actions ------------------------------------------------------------
    def action_stop(self) -> None:
        """Stop testing gracefully."""
        with self._lock:
            if self._stopped or self._ended:
                return
            self._stopped = True
        self.set_status("Stop requested — finishing current attempt…")
        try:
            self._on_stop()
        except Exception:  # noqa: BLE001
            pass

    def action_resume(self) -> None:
        """Resume testing after a stop."""
        with self._lock:
            if not self._stopped or self._ended:
                return
            self._stopped = False
        self.set_status("Resuming…")
        try:
            self._on_resume()
        except Exception:  # noqa: BLE001
            pass

    def action_end(self) -> None:
        """End testing immediately."""
        with self._lock:
            self._ended = True
            self._stopped = True
        self.set_status("Ending test…")
        try:
            self._on_end()
        except Exception:  # noqa: BLE001
            pass
        self.app_ref.exit()

    def _on_body_entry_activated(self, key: str) -> None:
        if key == "stop":
            self.action_stop()
        elif key == "resume":
            self.action_resume()
        elif key == "end":
            self.action_end()

    def _on_action_activated(self, key: str) -> None:
        if key == "stop":
            self.action_stop()
        elif key == "resume":
            self.action_resume()
        elif key == "end":
            self.action_end()


class ProgressApp(App):
    """Textual app wrapper that hosts ProgressScreen."""

    def __init__(
        self,
        total_entries: int,
        num_windows: int,
        on_stop: Callable[[], None],
        on_resume: Callable[[], None],
        on_end: Callable[[], None],
    ) -> None:
        super().__init__()
        self.total_entries = total_entries
        self.num_windows = num_windows
        self._on_stop = on_stop
        self._on_resume = on_resume
        self._on_end = on_end
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
        if self.screen_instance is not None:
            self.call_from_thread(
                self.screen_instance.update_progress,
                window_idx, completed, total, result_str, ms,
            )

    def set_status(self, message: str) -> None:
        """Forward status messages to the screen (thread-safe)."""
        if self.screen_instance is not None:
            self.call_from_thread(self.screen_instance.set_status, message)

    def on_mount(self) -> None:
        self.screen_instance = ProgressScreen(
            self, self.total_entries, self.num_windows,
            self._on_stop, self._on_resume, self._on_end,
        )
        self.install_screen(self.screen_instance, name="progress")
        self.push_screen("progress")
