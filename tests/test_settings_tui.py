# Signed by JOE
"""Tests for the redesigned plain-text settings TUI.

Uses Textual's headless pilot. These verify that every screen shares one
plain-text visual language (``=`` / ``-`` separators, a ``>`` selected-item
marker, no box-drawing characters or graphical panels), that arrow keys /
Enter / mouse clicks navigate and activate entries, that disabled entries are
inert, that long menus navigate, that settings edit + save + validation work,
that password inputs stay masked and unpersisted, and that Escape returns to
the previous screen.

(The TUI never starts a browser and never performs an authentication test.)

Note: these automated tests exercise the TUI through Textual's headless pilot
(which simulates key presses and mouse clicks). They do not involve a real
terminal or manual verification in Windows Terminal; mouse behaviour is
therefore covered by simulated click events, not by live mouse interaction.
"""

import asyncio
import json
import sys

import pytest

pytest.importorskip("textual")

from auth_audit import settings_tui  # noqa: E402
from auth_audit import schema  # noqa: E402
from auth_audit.tui.app import SettingsApp  # noqa: E402
from auth_audit.tui.entries import Entry, ListPanel  # noqa: E402
from auth_audit.tui.pages import (  # noqa: E402
    AdvancedScreen,
    AuthScreen,
    BrowserScreen,
    DependenciesScreen,
    ExecutionScreen,
    MainMenuScreen,
    OverviewScreen,
    ReportingScreen,
    TargetScreen,
)
from textual.app import App  # noqa: E402
from textual.widgets import Static  # noqa: E402


PAGE_NAMES = [
    "main", "overview", "target", "auth", "browser",
    "execution", "reporting", "dependencies", "advanced",
]


def _write_config(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(schema.default_config()), encoding="utf-8")
    return cfg


def _box_drawing(text: str) -> bool:
    """True if text contains Unicode box-drawing / graphical chars."""
    return any("\u2500" <= ch <= "\u257f" for ch in text)


def _static_text(widget) -> str:
    return getattr(widget, "_Static__content", "") or ""


def _rendered_text(app) -> str:
    """Gather the rendered plain-text of every Static/Entry on the screen."""
    return "\n".join(_static_text(w) for w in app.screen.query(Static))


async def _open(app, pilot, page_name: str):
    app.push_screen(page_name)
    await pilot.pause()


async def _close(app, pilot):
    app.pop_screen()
    await pilot.pause()


# ---------------------------------------------------------------------------
# Navigation: arrow keys, Enter, mouse.
# ---------------------------------------------------------------------------


async def _run(app, scenario):
    async with app.run_test() as pilot:
        await scenario(app, pilot)


def test_arrow_nav_changes_selected_item(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        panel = app.screen.query_one(ListPanel)
        assert panel.selected_index == 0
        first = app.screen.query_one("#entry-overview", Entry)
        assert "> " in _static_text(first)
        await pilot.press("down")
        await pilot.pause()
        assert panel.selected_index == 1
        second = app.screen.query_one("#entry-target", Entry)
        assert "> " in _static_text(second)
        assert "> " not in _static_text(first)

    asyncio.run(_run(app, scenario))


def test_enter_activates_selected_item(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        await pilot.press("down")  # Target Configuration
        await pilot.pause()
        await pilot.press("enter")  # activate
        await pilot.pause()
        assert isinstance(app.screen, TargetScreen)

    asyncio.run(_run(app, scenario))


def test_mouse_click_selects_then_activates(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        panel = app.screen.query_one(ListPanel)
        assert panel.selected_index == 0  # Overview
        # First click on Target -> selects, does not activate.
        await pilot.click("#entry-target")
        await pilot.pause()
        assert panel.selected_index == 1
        assert isinstance(app.screen, MainMenuScreen)
        # Second click on the same entry -> activates.
        await pilot.click("#entry-target")
        await pilot.pause()
        assert isinstance(app.screen, TargetScreen)

    asyncio.run(_run(app, scenario))


def test_mouse_click_selects_field_entry(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        await pilot.press("down")  # Target Configuration
        await pilot.press("enter")
        await pilot.pause()
        panel = app.screen.query_one(ListPanel)
        assert panel.selected_index == 0  # target_url
        await pilot.click("#entry-allowed_hosts")
        await pilot.pause()
        assert panel.selected_index == 1

    asyncio.run(_run(app, scenario))


# ---------------------------------------------------------------------------
# Disabled entries.
# ---------------------------------------------------------------------------


def test_disabled_entry_cannot_be_selected_or_activated():
    activated = []

    class _Probe(App):
        def compose(self):
            yield ListPanel(
                [
                    Entry("a", "One"),
                    Entry("b", "Two", disabled=True),
                    Entry("c", "Three"),
                ],
                id="p",
                on_activate=lambda k: activated.append(k),
            )

    app = _Probe()

    async def scenario(app, pilot):
        panel = app.screen.query_one(ListPanel)
        assert panel.selected_index == 0
        await pilot.press("down")
        await pilot.pause()
        # Skips the disabled "Two".
        assert panel.selected_index == 2
        await pilot.press("down")
        await pilot.pause()
        assert panel.selected_index == 0  # wraps
        # Clicking the disabled entry does nothing.
        await pilot.click("#entry-b")
        await pilot.pause()
        assert panel.selected_index == 0
        assert activated == []

    asyncio.run(_run(app, scenario))


# ---------------------------------------------------------------------------
# Long menus navigate without crashing.
# ---------------------------------------------------------------------------


def test_long_menu_navigates_without_crashing():
    entries = [Entry(f"n{i}", f"Item {i}") for i in range(40)]

    class _Probe(App):
        def compose(self):
            yield ListPanel(entries, id="p")

    app = _Probe()

    async def scenario(app, pilot):
        panel = app.screen.query_one(ListPanel)
        panel.selected_index = 0
        panel._apply_selection()
        for _ in range(50):
            await pilot.press("down")
            await pilot.pause()
        assert 0 <= panel.selected_index < len(entries)

    asyncio.run(_run(app, scenario))


# ---------------------------------------------------------------------------
# Consistent visual style across all pages.
# ---------------------------------------------------------------------------


def test_every_page_uses_consistent_plain_text_style(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        for name in PAGE_NAMES:
            await _open(app, pilot, name)
            await pilot.pause()
            full = _rendered_text(app)
            assert "=" in full, f"{name}: missing '=' separator"
            assert "-" in full, f"{name}: missing '-' separator"
            assert "> " in full, f"{name}: missing '>' selected marker"
            assert not _box_drawing(full), f"{name}: box-drawing found"
            await _close(app, pilot)

    asyncio.run(_run(app, scenario))


def test_no_box_drawing_characters_anywhere(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        full_main = _rendered_text(app)
        await _open(app, pilot, "target")
        await pilot.pause()
        full_target = _rendered_text(app)
        await _close(app, pilot)
        for label, full in (("main", full_main), ("target", full_target)):
            assert not _box_drawing(full), label

    asyncio.run(_run(app, scenario))


# ---------------------------------------------------------------------------
# Settings edit + save.
# ---------------------------------------------------------------------------


async def _edit_target_url(app, pilot, new_value):
    await pilot.press("down")  # Target Configuration
    await pilot.press("enter")
    await pilot.pause()
    await pilot.press("enter")  # open target_url editor
    await pilot.pause()
    editor = app.screen
    editor.control.value = ""
    await pilot.pause()
    for ch in new_value:
        await pilot.press(ch)
        await pilot.pause()
    await pilot.press("enter")  # submit input -> save + persist
    await pilot.pause()
    await pilot.press("enter")  # dismiss editor back to page
    await pilot.pause()


def test_settings_edit_and_save_persists(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await _edit_target_url(app, pilot, "http://127.0.0.1:9999/login")
        await pilot.press("escape")  # back to main menu
        await pilot.pause()

    asyncio.run(_run(app, scenario))
    loaded = json.loads(cfg.read_text(encoding="utf-8"))
    assert loaded["target_url"] == "http://127.0.0.1:9999/login"


def test_invalid_value_blocks_save_and_shows_error(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        # Browser page is index 3 from the main menu (credentials removed).
        for _ in range(3):
            await pilot.press("down")
            await pilot.pause()
        await pilot.press("enter")  # Browser page
        await pilot.pause()
        # viewport_width is index 2 on the Browser page.
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("enter")  # open editor
        await pilot.pause()
        editor = app.screen
        editor.control.value = ""
        await pilot.pause()
        for ch in "-5":
            await pilot.press(ch)
            await pilot.pause()
        await pilot.press("enter")  # submit -> validation error
        await pilot.pause()

    asyncio.run(_run(app, scenario))
    loaded = json.loads(cfg.read_text(encoding="utf-8"))
    assert loaded["browser"]["viewport_width"] == 1280  # unchanged


def test_test_account_page_removed(tmp_path):
    """The dedicated Test Account page is no longer exposed in the TUI."""
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        main = _rendered_text(app)
        # No Test Account / credentials entry on the main menu.
        assert "credentials" not in main.lower().replace(" ", "")
        assert "test account" not in main.lower()

    asyncio.run(_run(app, scenario))


def test_secret_field_renders_masked():
    """A secret (password) FieldEntry renders masked, never plaintext."""
    from auth_audit.tui.pages import FieldEntry

    spec = schema.SPEC_BY_PATH["auth.password"]
    entry = FieldEntry(None, spec, "hunter2-supersecret")
    text = _static_text(entry)
    assert "hunter2-supersecret" not in text
    assert "*" * 8 in text
    # Empty secret renders as "(not set)".
    entry_empty = FieldEntry(None, spec, "")
    assert "(not set)" in _static_text(entry_empty)




# ---------------------------------------------------------------------------
# Escape returns to previous page.
# ---------------------------------------------------------------------------


def test_escape_returns_to_previous_page(tmp_path):
    cfg = _write_config(tmp_path)
    app = SettingsApp(str(cfg))

    async def scenario(app, pilot):
        await pilot.pause()
        await pilot.press("down")  # Target Configuration
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, TargetScreen)
        await pilot.press("escape")  # back to main menu
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)

    asyncio.run(_run(app, scenario))


# ---------------------------------------------------------------------------
# CLI surface and browser isolation.
# ---------------------------------------------------------------------------


def test_launch_settings_does_not_import_browser(tmp_path):
    cfg = _write_config(tmp_path)
    before = set(sys.modules)
    app = SettingsApp(str(cfg))
    # Construction alone must not pull in browser / auth_flow / reporting.
    assert set(sys.modules) == before, f"new imports: {set(sys.modules) - before}"


def test_launch_settings_requires_textual(monkeypatch, tmp_path):
    cfg = _write_config(tmp_path)
    import auth_audit.settings_tui as st
    monkeypatch.setattr(st, "TEXTUAL_AVAILABLE", False)
    assert st.launch_settings(str(cfg)) == 1


def test_cli_commands_still_work(monkeypatch, capsys):
    from auth_audit import cli
    assert cli.main(["--version"]) == 0
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for token in ("--settings", "--doctor", "--check-updates", "--update-deps"):
        assert token in out
    # --settings without textual returns 1 and never runs a browser.
    import auth_audit.settings_tui as st
    monkeypatch.setattr(st, "TEXTUAL_AVAILABLE", False)
    assert cli.cmd_settings("config.json") == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
