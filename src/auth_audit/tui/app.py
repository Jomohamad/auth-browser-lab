# Signed by JOE
"""The settings application: screen stack, working config, and save flow.

The TUI never starts a browser and never performs an authentication test.
Edits are applied to an in-memory working copy of the config and persisted
atomically (with a timestamped backup) only on explicit Save.  Secrets are
never written into the JSON config.

Screen stack
------------
The main menu sits at the bottom of the stack.  Opening a settings page
pushes a screen on top; opening a field editor pushes another screen.
Popping a screen reveals the one beneath with its selection and scroll
position intact, so the selected item is preserved when returning from a
child page.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from textual.app import App

from .. import schema
from .pages import (
    AdvancedScreen,
    AuthScreen,
    BrowserScreen,
    ExecutionScreen,
    MainMenuScreen,
    OverviewScreen,
    ReportingScreen,
    TargetScreen,
    DependenciesScreen,
)
from .confirm import ConfirmScreen


class SettingsApp(App):
    """Interactive settings TUI application."""

    TITLE = "AUTH BROWSER LAB — Settings"

    def __init__(self, config_path: str) -> None:
        super().__init__()
        self.config_path = Path(config_path)
        if self.config_path.exists():
            try:
                from ..config import load_raw_config

                self._saved: Dict[str, Any] = copy.deepcopy(
                    load_raw_config(self.config_path)
                )
            except Exception:  # noqa: BLE001 - fall back to safe defaults
                self._saved = copy.deepcopy(schema.default_config())
        else:
            self._saved = copy.deepcopy(schema.default_config())
        self.working: Dict[str, Any] = copy.deepcopy(self._saved)
        self.dirty = self._is_dirty()

    # -- lifecycle ---------------------------------------------------------
    def on_mount(self) -> None:
        # Install every page once; screens stay mounted across push/pop so
        # selection and scroll position are preserved when returning.
        self.install_screen(MainMenuScreen(self), name="main")
        self.install_screen(OverviewScreen(self), name="overview")
        self.install_screen(TargetScreen(self), name="target")
        self.install_screen(AuthScreen(self), name="auth")
        self.install_screen(BrowserScreen(self), name="browser")
        self.install_screen(ExecutionScreen(self), name="execution")
        self.install_screen(ReportingScreen(self), name="reporting")
        self.install_screen(DependenciesScreen(self), name="dependencies")
        self.install_screen(AdvancedScreen(self), name="advanced")
        self.push_screen("main")

    # -- working config ---------------------------------------------------
    def get(self, path: str) -> Any:
        return schema.get_value(self.working, path)

    def set(self, path: str, value: Any) -> None:
        schema.set_value(self.working, path, value)
        self.dirty = self._is_dirty()

    def spec(self, path: str):
        return schema.SPEC_BY_PATH.get(path)

    def _is_dirty(self) -> bool:
        return (
            json.dumps(self.working, sort_keys=True)
            != json.dumps(self._saved, sort_keys=True)
        )

    # -- persistence ------------------------------------------------------
    def commit_save(self) -> Tuple[bool, List[str], Optional[str]]:
        """Validate and persist the working config atomically with backup."""
        ok, errors, backup = schema.save_config(
            str(self.config_path), self.working, validate=True, backup=True
        )
        if ok:
            self._saved = copy.deepcopy(self.working)
            self.dirty = False
        return ok, errors, backup

    def serialized_saved(self) -> str:
        return json.dumps(self._saved, sort_keys=True)

    # -- navigation -------------------------------------------------------
    def push_page(self, page_id: str) -> None:
        self.push_screen(page_id)

    def open_field_editor(
        self, spec, current_value: Any, on_saved
    ) -> None:
        from .field_edit import FieldEditScreen

        self.push_screen(
            FieldEditScreen(self, spec, current_value, on_saved)
        )

    def show_confirm(self, message: str, callback) -> None:
        self.push_screen(ConfirmScreen(self, message), callback)

    def request_exit(self) -> None:
        """Called when the user asks to leave the main menu (Exit / Esc)."""
        if not self.dirty:
            self.exit()
            return
        self.show_confirm(
            "You have unsaved changes. Save before exiting?",
            self._on_exit_confirm,
        )

    def _on_exit_confirm(self, result: Optional[bool]) -> None:
        if result is None:
            return  # cancelled / no choice
        if result:
            ok, _errors, _backup = self.commit_save()
            if not ok:
                # Stay in the app so the user can fix invalid input.
                return
        self.exit()
