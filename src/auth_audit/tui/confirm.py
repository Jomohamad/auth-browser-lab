# Signed by JOE
"""Plain-text confirmation dialog.

A full-screen confirmation page (pushed on the stack) with the same visual
style as every other page: ``=`` / ``-`` separators and a ``>`` marker on the
selected option.  No decorative frame or dialog box is used.

The callback registered via ``App.push_screen(screen, callback)`` is invoked
by Textual with ``True`` (confirm), ``False`` (cancel) when the screen is
popped with a result.
"""

from __future__ import annotations

from .base import BaseScreen
from .entries import ActionEntry, ListPanel


class ConfirmScreen(BaseScreen):
    """Ask the user to confirm or cancel an action."""

    def __init__(self, app_ref, message: str) -> None:
        super().__init__(app_ref)
        self._message = message

    def page_title(self) -> str:
        return "Confirm"

    def page_subtitle(self) -> str:
        return self._message

    def _build_body(self):
        return ListPanel(
            [
                ActionEntry("yes", "[Yes]  Confirm"),
                ActionEntry("no", "[No]  Cancel"),
            ],
            selected_index=0,
            on_activate=self._on_activate,
        )

    def _on_activate(self, key: str) -> None:
        self.dismiss(result=(key == "yes"))

    def action_back(self) -> None:
        # Escape / Backspace -> cancel.
        self.dismiss(result=False)
