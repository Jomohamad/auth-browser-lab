# Signed by JOE
"""Tests for the Windows console always-on-top utility.

The OS/ctypes layer is monkeypatched so these run on any platform and never
touch the real console or crash.
"""

import pytest

from auth_audit import windows_console as wc


class TestPlatformGuard:
    def test_non_windows_not_attempted(self, monkeypatch):
        monkeypatch.setattr(wc, "is_windows", lambda: False)
        res = wc.enable_always_on_top()
        assert res.attempted is False
        assert res.enabled is False
        assert "only supported on Windows" in res.reason

    def test_disable_non_windows(self, monkeypatch):
        monkeypatch.setattr(wc, "is_windows", lambda: False)
        res = wc.disable_always_on_top()
        assert res.attempted is False


class TestEnableDisable:
    def test_missing_console_handle(self, monkeypatch):
        monkeypatch.setattr(wc, "is_windows", lambda: True)
        monkeypatch.setattr(wc, "get_console_hwnd", lambda: None)
        res = wc.enable_always_on_top()
        assert res.attempted is True
        assert res.enabled is False
        assert "No console window handle" in res.reason

    def test_enable_success(self, monkeypatch):
        monkeypatch.setattr(wc, "is_windows", lambda: True)
        monkeypatch.setattr(wc, "get_console_hwnd", lambda: 0x1234)
        monkeypatch.setattr(wc, "_set_pos", lambda hwnd, after: True)
        res = wc.enable_always_on_top()
        assert res.enabled is True
        assert "always-on-top" in res.reason.lower()

    def test_enable_failure_reports_honestly(self, monkeypatch):
        monkeypatch.setattr(wc, "is_windows", lambda: True)
        monkeypatch.setattr(wc, "get_console_hwnd", lambda: 0x1234)
        monkeypatch.setattr(wc, "_set_pos", lambda hwnd, after: False)
        res = wc.enable_always_on_top()
        assert res.enabled is False
        assert "could not be pinned" in res.reason

    def test_disable_uses_notopmost(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(wc, "is_windows", lambda: True)
        monkeypatch.setattr(wc, "get_console_hwnd", lambda: 0x1234)

        def fake_set(hwnd, after):
            seen["after"] = after
            return True

        monkeypatch.setattr(wc, "_set_pos", fake_set)
        res = wc.disable_always_on_top()
        assert seen["after"] == wc.HWND_NOTOPMOST
        assert res.enabled is False


class TestMaybeEnable:
    def test_disabled_flag_is_noop(self, monkeypatch):
        monkeypatch.setattr(wc, "is_windows", lambda: True)
        res = wc.maybe_enable(False)
        assert res.attempted is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
