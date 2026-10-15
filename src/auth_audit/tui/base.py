# Signed by JOE
"""Base screen and shared plain-text layout for every TUI page.

All screens share the same visual language:

    ============================================================
    AUTH BROWSER LAB — <page title>
    ============================================================

    <subtitle>

    <status message>

    <entries / body>

    ------------------------------------------------------------
    UP/DOWN: Navigate    ENTER: Select    ESC: Back
    MOUSE: Click to select
    ============================================================

No box-drawing characters, decorative frames, card-like panels, or
graphical layouts are used.  Separators are plain ``=`` / ``-`` text.
"""

from __future__ import annotations

from typing import Optional

from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static

from .entries import (
    DEFAULT_SEP_WIDTH,
    SEP_MAJOR,
    SEP_MINOR,
    separator,
    ListPanel,
)

APP_TITLE = "AUTH BROWSER LAB"

KEY_HINTS = (
    "UP/DOWN: Navigate    ENTER: Select    ESC: Back    "
    "MOUSE: Click to select"
)


class BaseScreen(Screen):
    """Base class for every settings page.

    Subclasses implement :meth:`_build_body` (usually a :class:`ListPanel`)
    and :meth:`action_back` (Escape behaviour).
    """

    CSS = """
    Screen { layout: vertical; }
    #header { height: auto; }
    #title { text-style: bold; color: $primary; }
    #subtitle { height: auto; color: $text; }
    #status { height: auto; color: $text; }
    #body { height: 1fr; }
    #footer { height: auto; color: $text-muted; }
    """

    #: Reactive sep width so the header / footer redraw on resize.
    _sep_width: int = DEFAULT_SEP_WIDTH

    def __init__(self, app_ref=None) -> None:
        super().__init__()
        self.app_ref = app_ref

    # -- composition -------------------------------------------------------
    def compose(self):
        yield Static(self._header_text(), id="header")
        yield Static(self._subtitle_text(), id="subtitle")
        yield Static("", id="status")
        yield self._build_body()
        yield Static("", id="spacer")
        yield Static(self._footer_text(), id="footer")

    def _build_body(self):
        """Assemble the scrollable body panel from body entries + actions.

        Entries are navigable with Up/Down and activatable with Enter.  The
        activation handler is the existing ``_on_body_entry_activated`` which
        subclasses already implement for every key (field/menu entries *and*
        action keys such as Save / Back / Exit).
        """
        entries = list(self._build_body_entries()) + list(self._build_actions())
        return ListPanel(
            entries,
            selected_index=0,
            on_activate=self._on_entry_activated,
            on_select=self._on_entry_selected,
            id="body",
        )

    def _on_entry_activated(self, key: str) -> None:
        """Dispatch an Enter/click activation to the body entry handler."""
        self._on_body_entry_activated(key)

    def _on_body_entry_activated(self, key: str) -> None:
        """Handle activation of a body/menu entry. Override in subclasses."""
        pass

    def _on_action_activated(self, key: str) -> None:
        """Handle activation of an action entry. Override in subclasses."""
        pass

    def _on_entry_selected(self, key: str) -> None:
        """Handle the selection moving to a different entry."""
        pass

    def action_back(self):  # pragma: no cover - overridden by subclasses
        """Escape / Backspace behaviour."""
        raise NotImplementedError

    # -- rendering helpers -------------------------------------------------
    def _header_text(self) -> str:
        return "\n".join(
            (
                separator(SEP_MAJOR, self._sep_width),
                f"{APP_TITLE} — {self.page_title()}",
                separator(SEP_MAJOR, self._sep_width),
            )
        )

    def _subtitle_text(self) -> str:
        return self.page_subtitle()

    def _footer_text(self) -> str:
        return "\n".join(
            (
                separator(SEP_MINOR, self._sep_width),
                KEY_HINTS,
                separator(SEP_MAJOR, self._sep_width),
            )
        )

    def page_title(self) -> str:  # pragma: no cover - overridden
        return "Settings"

    def page_subtitle(self) -> str:
        return ""

    # -- keyboard ----------------------------------------------------------
    def on_key(self, event) -> None:  # textual.events.Key
        if event.key == "escape":
            event.stop()
            self.action_back()

    # -- resize ------------------------------------------------------------
    def on_mount(self) -> None:
        self._refresh_sep_width()
        self._redraw_chrome()
        body = self._body_widget()
        if body is not None:
            try:
                body.focus()
            except Exception:  # noqa: BLE001
                pass

    def on_resize(self) -> None:
        self._refresh_sep_width()
        self._redraw_chrome()

    def _refresh_sep_width(self) -> None:
        width = self.size.width
        self._sep_width = max(20, min(DEFAULT_SEP_WIDTH, width - 4))

    def _redraw_chrome(self) -> None:
        try:
            self.query_one("#header", Static).update(self._header_text())
        except Exception:  # noqa: BLE001
            pass
        try:
            self.query_one("#footer", Static).update(self._footer_text())
        except Exception:  # noqa: BLE001
            pass
        try:
            self.query_one("#subtitle", Static).update(self._subtitle_text())
        except Exception:  # noqa: BLE001
            pass

    def _body_widget(self):  # helper for focus
        try:
            return self.query_one("#body")
        except Exception:  # noqa: BLE001
            return None

    # -- status messages ---------------------------------------------------
    def set_status(self, message: str, level: str = "info") -> None:
        """Show a transient status message (info / warn / error)."""
        try:
            widget = self.query_one("#status", Static)
        except Exception:  # noqa: BLE001
            return
        prefix = {"info": "", "warn": "[WARN] ", "error": "[ERROR] "}.get(
            level, ""
        )
        widget.update(f"{prefix}{message}")

    def clear_status(self) -> None:
        self.set_status("")
