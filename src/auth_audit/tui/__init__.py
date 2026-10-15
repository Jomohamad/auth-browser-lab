# Signed by JOE
"""Plain-text, line-based interactive settings TUI.

Built on Textual. Every screen uses the same visual language: plain text
labels, ``=`` / ``-`` horizontal separators, a ``>`` selected-item marker,
and consistent keyboard / mouse navigation.  No box-drawing characters,
decorative frames, card-like panels, or graphical layouts are used.

The heavy lifting (defaults, coercion, validation, atomic save, secret
handling) continues to live in :mod:`auth_audit.schema` and
:mod:`auth_audit.config`; this package is purely the presentation layer.

Launch with::

    python tester.py --settings
"""

from .app import SettingsApp
from .base import BaseScreen
from .entries import (
    ActionEntry,
    Entry,
    ListPanel,
    MenuEntry,
    SeparatorEntry,
    StaticEntry,
)

__all__ = [
    "SettingsApp",
    "BaseScreen",
    "ListPanel",
    "Entry",
    "MenuEntry",
    "ActionEntry",
    "StaticEntry",
    "SeparatorEntry",
]
