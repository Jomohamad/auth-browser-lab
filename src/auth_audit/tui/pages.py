# Signed by JOE
"""Every settings page, sharing one plain-text design.

Each page uses a two-area layout:

* A scrollable body (``#body``) holding field / menu entries navigable with
  Up/Down and Enter.
* An always-visible action bar (``#actions``) holding ``[Save]``,
  ``[Reset page]``, ``[Reset all]`` and ``[Back]`` / ``[Exit]`` buttons.

The ``credentials`` (Test Account) page is intentionally absent: the masked
password field is not exposed as a standalone page here, keeping the secret out
of the TUI surface while leaving runtime resolution (env / Credential Manager /
prompt) unchanged.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

from typing import TYPE_CHECKING

from textual.widgets import Static

from .. import schema
from .base import BaseScreen
from .entries import (
    ActionEntry,
    Entry,
    ListPanel,
    MenuEntry,
    SeparatorEntry,
    SEP_MAJOR,
    SEP_MINOR,
    StaticEntry,
)

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from .app import SettingsApp

IS_WINDOWS = sys.platform == "win32"

# Page ids intentionally excluded from the TUI menu (removed pages).
EXCLUDED_PAGE_IDS = {"credentials"}


class FieldEntry(Entry):
    """A single editable settings row shown on a settings page."""

    def __init__(self, app_ref: "SettingsApp", spec, value) -> None:
        self.app_ref = app_ref
        self.spec = spec
        disabled = spec.path == "always_on_top" and not IS_WINDOWS
        super().__init__(spec.path, self._fmt(value), disabled=disabled)

    def _fmt(self, value) -> str:
        s = self.spec
        if s.type == schema.FieldType.BOOL:
            return f"[{'X' if value else ' '}] {s.label}"
        if getattr(s, "secret", False):
            masked = "*" * 8 if value else ""
            return f"{s.label}: {masked if masked else '(not set)'}"
        if s.type == schema.FieldType.STRLIST:
            items = [str(x) for x in (value if isinstance(value, (list, tuple)) else [])]
            return f"{s.label}: {', '.join(items) if items else '(none)'}"
        return f"{s.label}: {value}"

    def redraw(self, value) -> None:
        self.set_text(self._fmt(value))

    def handle_horizontal(self, direction: str) -> bool:
        """Left/Right cycle ENUM choices while this row is selected."""
        s = self.spec
        if s.type != schema.FieldType.ENUM or not s.choices:
            return False
        current = self.app_ref.get(s.path)
        try:
            idx = list(s.choices).index(current)
        except ValueError:
            idx = 0
        step = 1 if direction == "right" else -1
        idx = (idx + step) % len(s.choices)
        new_value = s.choices[idx]
        schema.set_value(self.app_ref.working, s.path, new_value)
        self.app_ref.dirty = self.app_ref._is_dirty()
        self.redraw(new_value)
        return True


class PageScreen(BaseScreen):
    """Base class for an editable settings page."""

    PAGE_ID = "settings"
    TITLE = "Settings"
    SUBTITLE = ""

    def __init__(self, app_ref: "SettingsApp") -> None:
        super().__init__(app_ref)
        self._field_entries: dict = {}

    def page_title(self) -> str:
        return self.TITLE

    def page_subtitle(self) -> str:
        return self.SUBTITLE

    def _build_body_entries(self) -> list:
        app = self.app_ref
        entries = []
        for spec in schema.specs_for_page(self.PAGE_ID):
            value = app.get(spec.path)
            entry = FieldEntry(app, spec, value)
            entries.append(entry)
            self._field_entries[spec.path] = entry
        return entries

    def _build_actions(self):
        yield SeparatorEntry("actions-sep", SEP_MAJOR)
        yield ActionEntry("save", "(S) Save", can_focus=True)
        yield ActionEntry("reset-page", "(R) Reset page", can_focus=True)
        yield ActionEntry("reset-all", "(A) Reset all", can_focus=True)
        yield ActionEntry("back", "(Esc) Back", can_focus=True)

    # -- keyboard shortcuts for action buttons ------------------------------
    BINDINGS = [
        ("s", "save", "Save"),
        ("r", "reset-page", "Reset page"),
        ("a", "reset-all", "Reset all"),
        ("escape", "back", "Back"),
    ]

    def action_save(self) -> None:
        self._do_save()

    def action_reset_page(self) -> None:
        self._reset_page()

    def action_reset_all(self) -> None:
        self._reset_all()

    def action_back(self) -> None:
        # Escape / Backspace -> return to the previous screen.
        self.app_ref.pop_screen()

    def _on_body_entry_activated(self, key: str) -> None:
        app = self.app_ref
        spec = app.spec(key)
        if spec is not None:
            app.open_field_editor(
                spec, app.get(key), on_saved=lambda: self._refresh_field(key)
            )
            return
        if key == "save":
            self._do_save()
        elif key == "reset-page":
            self._reset_page()
        elif key == "reset-all":
            self._reset_all()
        elif key == "back":
            app.pop_screen()

    def _on_action_activated(self, key: str) -> None:
        if key == "save":
            self._do_save()
        elif key == "reset-page":
            self._reset_page()
        elif key == "reset-all":
            self._reset_all()
        elif key == "back":
            self.app_ref.pop_screen()

    def _refresh_field(self, path: str) -> None:
        entry = self._field_entries.get(path)
        if entry is not None:
            entry.redraw(self.app_ref.get(path))
        self.set_status("Saved.", level="info")

    def _do_save(self) -> None:
        ok, errors, backup = self.app_ref.commit_save()
        if ok:
            note = ""
            if backup:
                note = f" (backup: {Path(backup).name})"
            self.set_status(f"Saved.{note}", level="info")
        else:
            self.set_status("Invalid: " + "; ".join(errors), level="error")
            self.app_ref.bell()

    def _reset_page(self) -> None:
        app = self.app_ref
        for spec in schema.specs_for_page(self.PAGE_ID):
            saved_val = schema.get_value(app._saved, spec.path)
            schema.set_value(app.working, spec.path, saved_val)
            entry = self._field_entries.get(spec.path)
            if entry is not None:
                entry.redraw(saved_val)
        app.dirty = app._is_dirty()
        self.set_status("Page reset to saved values.", level="info")

    def _reset_all(self) -> None:
        self.app_ref.show_confirm(
            "Reset ALL settings to safe defaults?",
            self._on_reset_all_confirmed,
        )

    def _on_reset_all_confirmed(self, result: bool) -> None:
        if not result:
            return
        app = self.app_ref
        app.working = copy.deepcopy(schema.default_config())
        app.dirty = True
        for path, entry in self._field_entries.items():
            entry.redraw(app.get(path))
        self.set_status("All settings reset to defaults.", level="info")


# ---------------------------------------------------------------------------
# Main menu.
# ---------------------------------------------------------------------------


class MainMenuScreen(BaseScreen):
    """Top-level menu: open a settings page or exit."""

    TITLE = "Main Menu"

    def __init__(self, app_ref: "SettingsApp") -> None:
        super().__init__(app_ref)

    def page_title(self) -> str:
        return self.TITLE

    def page_subtitle(self) -> str:
        return "Choose a page to view or edit."

    def _build_body_entries(self) -> list:
        app = self.app_ref
        entries = []
        for page in schema.PAGES:
            if page["id"] in EXCLUDED_PAGE_IDS:
                continue
            entries.append(MenuEntry(page["id"], page["title"]))
        return entries

    def _build_actions(self):
        yield SeparatorEntry("actions-sep", SEP_MAJOR)
        yield ActionEntry("exit", "(X) Exit", can_focus=True)

    # -- keyboard shortcuts -------------------------------------------------
    BINDINGS = [
        ("x", "exit", "Exit"),
        ("escape", "back", "Back"),
    ]

    def action_exit(self) -> None:
        self.app_ref.request_exit()

    def action_back(self) -> None:
        self.app_ref.request_exit()

    def _on_body_entry_activated(self, key: str) -> None:
        if key == "exit":
            self.app_ref.request_exit()
        else:
            self.app_ref.push_page(key)

    def _on_action_activated(self, key: str) -> None:
        if key == "exit":
            self.app_ref.request_exit()


# ---------------------------------------------------------------------------
# Overview (read-only).
# ---------------------------------------------------------------------------


class OverviewScreen(PageScreen):
    PAGE_ID = "overview"
    TITLE = "Overview"
    SUBTITLE = "Read-only configuration and environment summary."

    def _build_body_entries(self) -> list:
        app = self.app_ref
        entries = [StaticEntry("overview-intro", "")]
        for line in self._overview_lines(app):
            entries.append(StaticEntry(f"ov-{len(entries)}", line))
        return entries

    def _build_actions(self):
        yield SeparatorEntry("actions-sep", SEP_MAJOR)
        yield ActionEntry("back", "(Esc) Back", can_focus=True)

    def _on_body_entry_activated(self, key: str) -> None:
        # Overview body entries are read-only; activation does nothing.
        pass

    @staticmethod
    def _overview_lines(app) -> list:
        lines = []
        try:
            from .. import __version__ as ver
        except Exception:  # noqa: BLE001
            ver = "n/a"
        lines.append(f"Application version : {ver}")
        lines.append(f"Config file         : {app.config_path}")
        try:
            from . import dependency_manager

            report = dependency_manager.check_updates()
            counts = report.summary_counts()
            lines.append(
                f"Python              : {report.python_version} "
                f"(>= {report.min_python}) "
                f"{'OK' if report.python_ok else 'FAIL'}"
            )
            lines.append(
                f"Network (PyPI)      : "
                f"{'reachable' if report.network_ok else 'unavailable (offline)'}"
            )
            lines.append(
                f"Dependencies        : outdated={counts['outdated']} "
                f"missing_required={counts['missing_required']}"
            )
        except Exception:  # noqa: BLE001
            lines.append("Dependencies        : (unavailable)")
        try:
            from ..config import load_config

            cfg = load_config(app.config_path)
            lines.append(
                f"Target host         : {cfg.target_hostname} "
                f"(validated)"
            )
        except Exception:  # noqa: BLE001
            lines.append("Target host         : (invalid config)")
        lines.append("Secret storage      : env / Windows Credential Manager / prompt")
        try:
            from .. import windows_console

            lines.append(
                f"Always-on-top       : supported={windows_console.is_windows()}"
            )
        except Exception:  # noqa: BLE001
            lines.append("Always-on-top       : supported=False")
        return lines


# ---------------------------------------------------------------------------
# Individual settings pages.
# ---------------------------------------------------------------------------


class TargetScreen(PageScreen):
    PAGE_ID = "target"
    TITLE = "Target Configuration"
    SUBTITLE = "Login page URL and the hosts you are authorized to test."


class AuthScreen(PageScreen):
    PAGE_ID = "auth"
    TITLE = "Authentication Configuration"
    SUBTITLE = "Provider, form selectors, and success / failure indicators."


class BrowserScreen(PageScreen):
    PAGE_ID = "browser"
    TITLE = "Browser Settings"
    SUBTITLE = "Engine, headless mode, viewport, timeouts, and console options."


class ExecutionScreen(PageScreen):
    PAGE_ID = "execution"
    TITLE = "Test Execution Settings"
    SUBTITLE = "Concurrent windows, resume-on-stop, security-challenge policy, password file."


class ReportingScreen(PageScreen):
    PAGE_ID = "reporting"
    TITLE = "Reporting"
    SUBTITLE = "Report directory, timestamps, log level, retention, and verbosity."


class DependenciesScreen(PageScreen):
    PAGE_ID = "dependencies"
    TITLE = "Dependencies and Tools"
    SUBTITLE = "Installed versions and compatible update checks."


class AdvancedScreen(PageScreen):
    PAGE_ID = "security"
    TITLE = "Advanced Settings"
    SUBTITLE = "Challenge HTTP codes, blocking patterns, and CAPTCHA / MFA selectors."
