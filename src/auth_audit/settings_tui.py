# Signed by JOE
"""Interactive settings Terminal User Interface (Textual).

    python tester.py --settings

Launching the TUI never starts a browser or performs any authentication test.
Users navigate pages with the arrow keys and the mouse, edit values with
keyboard-accessible controls (text input, masked password input, dropdowns,
checkboxes, numeric inputs), validate, save (atomically, with a backup, and
never persisting secrets), and exit.  Exiting with unsaved changes prompts for
confirmation.

Secret fields are masked and are never shown again on reopen; the password is
resolved at run time (env / Windows Credential Manager / prompt), not stored in
the JSON config.

The heavy lifting (defaults, coercion, validation, atomic save) lives in
``schema.py``; this module is the presentation layer.  The actual screens live
in the :mod:`auth_audit.tui` package.
"""

from __future__ import annotations

import sys

# Textual is an optional dependency. Import lazily and fail with a clear
# message if it is missing so the rest of the tool works without it.
try:  # pragma: no cover - exercised only when textual is installed
    from .tui.app import SettingsApp

    TEXTUAL_AVAILABLE = True
except Exception:  # noqa: BLE001
    TEXTUAL_AVAILABLE = False
    SettingsApp = object  # type: ignore


def launch_settings(config_path: str) -> int:
    """Entry point used by the CLI. Returns a process exit code."""
    if not TEXTUAL_AVAILABLE:
        print(
            "The interactive settings TUI requires the optional 'textual' "
            "dependency.\nInstall it with:  python -m pip install \"textual>=0.80\"",
            file=sys.stderr,
        )
        return 1
    app = SettingsApp(config_path)
    app.run()
    return 0


__all__ = ["launch_settings", "SettingsApp", "TEXTUAL_AVAILABLE"]
