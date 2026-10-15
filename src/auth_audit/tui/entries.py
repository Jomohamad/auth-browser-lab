# Signed by JOE
"""Plain-text line-based menu / list panel.

Every renderable line is plain text: indentation, a ``>`` selected-item
marker, and horizontal ``=`` / ``-`` separators.  The panel is navigable with
the Up/Down arrow keys, activatable with Enter, and selectable / activatable
with mouse clicks.  Disabled entries are dimmed, cannot be selected, and
cannot be activated.

No box-drawing characters, decorative frames, or graphical panels are used.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from textual.containers import ScrollableContainer
from textual.widget import Widget
from textual.widgets import Static

# ---------------------------------------------------------------------------
# Visual constants (plain text only).
# ---------------------------------------------------------------------------

INDENT = "    "
SELECTED_MARKER = "> "
UNSELECTED_MARKER = "  "
SEP_MAJOR = "="
SEP_MINOR = "-"
DEFAULT_SEP_WIDTH = 60


def separator(char: str = SEP_MAJOR, width: int = DEFAULT_SEP_WIDTH) -> str:
    """Return a horizontal separator line of plain text."""
    return char * max(10, min(width, DEFAULT_SEP_WIDTH))


# ---------------------------------------------------------------------------
# Individual entry (a single selectable line).
# ---------------------------------------------------------------------------


class Entry(Static, can_focus=False):
    """A single selectable plain-text line.

    Parameters
    ----------
    key:
        Stable identifier used for navigation / activation callbacks.
    text:
        The label (already formatted, e.g. ``"Target URL"``).
    selected:
        Whether this entry is currently selected (renders the ``>`` marker).
    disabled:
        Whether the entry is disabled (dimmed, unselectable, unactivatable).
    """

    def __init__(
        self,
        key: str,
        text: str,
        *,
        selected: bool = False,
        disabled: bool = False,
    ) -> None:
        # Textual ids must be simple identifiers; dots/slashes in spec paths
        # are sanitized for the DOM id while the original key is preserved.
        safe_key = key.replace(".", "__").replace("/", "_")
        super().__init__(self._format_text(text, selected, disabled), id=f"entry-{safe_key}")
        self.key = key
        self._text = text
        self.selected = selected
        self.disabled = disabled
        self._panel: Optional["ListPanel"] = None

    def dom_id(self) -> str:
        return f"entry-{self.key.replace('.', '__').replace('/', '_')}"

    @staticmethod
    def _format_text(text: str, selected: bool, disabled: bool) -> str:
        marker = SELECTED_MARKER if selected else UNSELECTED_MARKER
        line = f"{INDENT}{marker}{text}"
        if disabled:
            line = f"{line}   (disabled)"
        return line

    def set_state(self, *, selected: bool, disabled: bool) -> None:
        self.selected = selected
        self.disabled = disabled
        self.update(self._format_text(self._text, self.selected, self.disabled))

    def set_text(self, text: str) -> None:
        self._text = text
        self.update(self._format_text(self._text, self.selected, self.disabled))

    def handle_horizontal(self, direction: str) -> bool:
        """Handle Left/Right for entries that support it (e.g. enums).

        Return True if the key was consumed.
        """
        return False

    def on_click(self, event) -> None:  # type: ignore[override]
        """Mouse click: select this entry, or activate if already selected."""
        if self._panel is not None:
            self._panel.on_entry_clicked(self)


class MenuEntry(Entry):
    """A navigable menu item (e.g. a settings page or an action)."""


class ActionEntry(Entry):
    """A menu-styled action such as ``[Save]`` or ``[Back]``."""


class StaticEntry(Entry):
    """Non-selectable informational line (never the selection target)."""

    def __init__(self, key: str, text: str) -> None:
        super().__init__(key, text, selected=False, disabled=True)


class SeparatorEntry(Entry):
    """A horizontal ``=`` / ``-`` separator line (non-selectable)."""

    def __init__(self, key: str, char: str = SEP_MAJOR, width: int = DEFAULT_SEP_WIDTH):
        super().__init__(key, separator(char, width), selected=False, disabled=True)


# ---------------------------------------------------------------------------
# List panel: a scrollable plain-text list of entries.
# ---------------------------------------------------------------------------


class ListPanel(ScrollableContainer, can_focus=True):
    """A scrollable list of :class:`Entry` widgets.

    Navigation
    ----------
    * Up / Down: move the selection (skipping disabled entries).
    * Enter: activate the selected entry.
    * Left / Right: handed to the selected entry (e.g. enum cycling).
    * Mouse click: select an entry; click the same entry again to activate it.

    Callbacks
    ---------
    on_activate(key):
        Invoked when an entry is activated (Enter or repeat click).
    on_select(key):
        Invoked when the selection moves to a different entry.
    """

    def __init__(
        self,
        entries: List[Entry],
        *,
        selected_index: int = 0,
        on_activate: Optional[Callable[[str], None]] = None,
        on_select: Optional[Callable[[str], None]] = None,
        id: str | None = None,
    ) -> None:
        super().__init__(id=id)
        self._entries_spec = entries
        self._on_activate = on_activate
        self._on_select = on_select
        self.selected_index = selected_index
        self._entry_widgets: List[Entry] = []

    # -- composition -------------------------------------------------------
    def compose(self):
        for entry in self._entries_spec:
            entry._panel = self
            self._entry_widgets.append(entry)
            yield entry

    def on_mount(self) -> None:
        self._apply_selection()
        self.focus()

    # -- selection ---------------------------------------------------------
    def _apply_selection(self) -> None:
        for i, entry in enumerate(self._entry_widgets):
            entry.set_state(selected=(i == self.selected_index), disabled=entry.disabled)
        try:
            self._entry_widgets[self.selected_index].scroll_visible()
        except Exception:  # noqa: BLE001 - best effort scroll
            pass

    def _move(self, delta: int) -> None:
        n = len(self._entry_widgets)
        if n == 0:
            return
        idx = self.selected_index
        steps = 0
        while steps < n:
            idx = (idx + delta) % n
            if not self._entry_widgets[idx].disabled:
                break
            steps += 1
        else:
            return  # every entry is disabled
        if idx != self.selected_index:
            self.selected_index = idx
            self._apply_selection()
            if self._on_select is not None:
                self._on_select(self._entry_widgets[idx].key)

    def _activate(self) -> None:
        if not self._entry_widgets:
            return
        entry = self._entry_widgets[self.selected_index]
        if entry.disabled:
            return
        if self._on_activate is not None:
            self._on_activate(entry.key)

    def _horizontal(self, direction: str) -> None:
        if not self._entry_widgets:
            return
        entry = self._entry_widgets[self.selected_index]
        if entry.disabled:
            return
        handler = getattr(entry, "handle_horizontal", None)
        if callable(handler) and handler(direction):
            return

    # -- keyboard ----------------------------------------------------------
    def on_key(self, event) -> None:  # textual.events.Key
        key = event.key
        if key == "down":
            event.stop()
            self._move(+1)
        elif key == "up":
            event.stop()
            self._move(-1)
        elif key == "enter":
            event.stop()
            self._activate()
        elif key in ("left", "right"):
            event.stop()
            self._horizontal(key)

    # -- mouse -------------------------------------------------------------
    def on_entry_clicked(self, entry: Entry) -> None:
        """Called by an :class:`Entry` when it is clicked."""
        if entry.disabled:
            return
        current = self._entry_widgets[self.selected_index]
        if entry.key == current.key:
            # Same entry clicked again -> activate.
            self._activate()
        else:
            self.selected_index = self._entry_widgets.index(entry)
            self._apply_selection()
            if self._on_select is not None:
                self._on_select(entry.key)
        self.focus()
