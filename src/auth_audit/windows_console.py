# Signed by JOE
"""Windows console always-on-top utility.

Best-effort, opt-in, and safe by construction:

  * Only runs on Windows; on other platforms it reports "not attempted".
  * Uses ``GetConsoleWindow`` to find the console HWND. If there is none (IDE
    terminals, embedded/redirected consoles) it reports that gracefully.
  * Calls ``SetWindowPos`` with ``SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE``:
    it never steals keyboard focus and never moves/resizes the window without
    user approval.
  * Never raises on any failure path; returns a small result object with a
    human-readable ``reason`` so the caller can warn the user honestly.

Never claim the terminal is always on top if the operation failed.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

# Win32 constants used with SetWindowPosW.
HWND_TOPMOST = -1
HWND_NOTOPMOST = -2
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOACTIVATE = 0x0010


def is_windows() -> bool:
    return sys.platform.startswith("win")


@dataclass
class TopMostResult:
    attempted: bool
    enabled: bool
    reason: str


def get_console_hwnd():
    """Return the console window HWND on Windows, else None."""
    if not is_windows():
        return None
    try:
        import ctypes

        hwnd = ctypes.windll.kernel32.GetConsoleWindow()  # type: ignore[attr-defined]
        return hwnd or None
    except Exception:  # noqa: BLE001 - missing console, restricted terminal
        return None


def _load_set_window_pos():
    """Load SetWindowPos from user32.dll with an explicit signature.

    Note: ``SetWindowPos`` has no ``W``/``A`` suffix on Windows (it takes no
    string parameters, so no ANSI/Wide variant exists), so we try the bare name
    first, then the suffixed variants as a fallback.

    Returns a callable, or None if the function cannot be resolved.  Never
    raises — the caller treats None as "operation unavailable".
    """
    import ctypes
    from ctypes import wintypes

    proto = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,   # hWnd
        wintypes.HWND,   # hWndInsertAfter
        wintypes.INT,    # X
        wintypes.INT,    # Y
        wintypes.INT,    # cx
        wintypes.INT,    # cy
        wintypes.UINT,   # uFlags
    )

    # Try bare name first (this is what actually exists for SetWindowPos).
    for name in ("SetWindowPos", "SetWindowPosW", "SetWindowPosA"):
        try:
            user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
            return proto((name, user32))
        except (AttributeError, OSError):
            continue

    # Fallback: ctypes.windll attribute access.
    try:
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        for name in ("SetWindowPos", "SetWindowPosW", "SetWindowPosA"):
            try:
                func = getattr(user32, name)
                func.argtypes = [
                    wintypes.HWND, wintypes.HWND, wintypes.INT, wintypes.INT,
                    wintypes.INT, wintypes.INT, wintypes.UINT,
                ]
                func.restype = wintypes.BOOL
                return func
            except AttributeError:
                continue
    except AttributeError:
        pass

    return None


# Loaded lazily on first use so the module imports cleanly everywhere.
_SET_WINDOW_POS = None


def _set_pos(hwnd, insert_after: int) -> bool:
    """Call SetWindowPos preserving position/size and without activating.

    Returns True on success, False if the API could not be invoked.  Never
    raises — pinning the console is best-effort.
    """
    global _SET_WINDOW_POS
    if _SET_WINDOW_POS is None:
        _SET_WINDOW_POS = _load_set_window_pos()
    if _SET_WINDOW_POS is None:
        return False
    flags = SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE
    try:
        result = _SET_WINDOW_POS(hwnd, insert_after, 0, 0, 0, 0, flags)
        return bool(result)
    except Exception:  # noqa: BLE001 - never crash on console pinning
        return False


def enable_always_on_top() -> TopMostResult:
    """Attempt to pin the current console window above others."""
    if not is_windows():
        return TopMostResult(
            attempted=False, enabled=False,
            reason="Always-on-top is only supported on Windows; skipping.",
        )

    hwnd = get_console_hwnd()
    if not hwnd:
        return TopMostResult(
            attempted=True, enabled=False,
            reason=(
                "No console window handle available (IDE/embedded terminal); "
                "cannot enable always-on-top."
            ),
        )

    if _set_pos(hwnd, HWND_TOPMOST):
        return TopMostResult(
            attempted=True, enabled=True,
            reason="Console window pinned as always-on-top.",
        )
    return TopMostResult(
        attempted=True, enabled=False,
        reason="SetWindowPos failed; the console could not be pinned on top.",
    )


def disable_always_on_top() -> TopMostResult:
    """Attempt to release a previously applied always-on-top state."""
    if not is_windows():
        return TopMostResult(
            attempted=False, enabled=False,
            reason="Always-on-top is only supported on Windows; skipping.",
        )

    hwnd = get_console_hwnd()
    if not hwnd:
        return TopMostResult(
            attempted=True, enabled=False,
            reason=(
                "No console window handle available (IDE/embedded terminal); "
                "nothing to release."
            ),
        )

    if _set_pos(hwnd, HWND_NOTOPMOST):
        return TopMostResult(
            attempted=True, enabled=False,
            reason="Console always-on-top released.",
        )
    return TopMostResult(
        attempted=True, enabled=True,
        reason="SetWindowPos failed; could not release always-on-top.",
    )


def maybe_enable(enabled: bool) -> TopMostResult:
    """Enable/disable according to a config flag; safe to call anywhere."""
    if enabled:
        return enable_always_on_top()
    return TopMostResult(
        attempted=False, enabled=False, reason="always_on_top disabled by config."
    )
