"""Headless checks for the runtime progress TUI."""

import asyncio

import pytest

pytest.importorskip("textual")

from auth_audit.tui.progress import ProgressApp
from textual.widgets import Button, Static


async def _run(app, scenario):
    async with app.run_test() as pilot:
        await scenario(app, pilot)


def test_progress_screen_renders_and_updates_from_worker_thread():
    app = ProgressApp(3, 2, lambda: None)

    async def scenario(app, pilot):
        await pilot.pause()
        screen = app.screen_instance
        assert screen is not None
        grid = screen.query_one("#progress-grid", Static).render().plain
        assert "(0/2)" in grid
        assert "(0/1)" in grid
        footer = screen.query_one("#footer", Static).render().plain
        assert footer.strip() == "=" * 60
        assert "UP/DOWN" not in footer

        await asyncio.to_thread(
            app.update_progress, 1, 1, 1, "INCONCLUSIVE", 42
        )
        await pilot.pause()
        grid = screen.query_one("#progress-grid", Static).render().plain
        assert "100.0% (1/1)" in grid
        assert "INCONCLUSIVE (42ms)" in grid
        eta = screen.query_one("#eta", Static).render().plain
        assert "Estimated remaining:" in eta
        assert "Calculating" not in eta

        assert len(screen.query("#action-bar Button")) == 1
        assert screen.query_one("#stop", Button)
        assert not screen.query("#resume")
        assert not screen.query("#end")

    asyncio.run(_run(app, scenario))


def test_stop_button_controls_the_active_callback_and_other_controls_are_removed():
    calls = []
    app = ProgressApp(
        1, 1,
        lambda: calls.append("stop"),
    )

    async def scenario(app, pilot):
        await pilot.pause()
        screen = app.screen_instance
        assert screen is not None
        await pilot.click("#stop")
        await pilot.pause()
        assert screen.is_stopped()
        assert calls == ["stop"]
        await pilot.press("r")
        await pilot.press("e")
        await pilot.pause()
        assert screen.is_stopped()
        assert calls == ["stop"]

    asyncio.run(_run(app, scenario))


def test_progress_values_are_bounded_and_unknown_windows_are_ignored():
    app = ProgressApp(2, 1, lambda: None)

    async def scenario(app, pilot):
        await pilot.pause()
        screen = app.screen_instance
        assert screen is not None
        screen.update_progress(0, 8, 2, "DONE", 10)
        screen.update_progress(4, 1, 1, "INVALID", 1)
        grid = screen.query_one("#progress-grid", Static).render().plain
        assert "100.0% (2/2)" in grid
        assert "DONE (10ms)" in grid

    asyncio.run(_run(app, scenario))


def test_on_ready_runs_after_progress_screen_is_mounted():
    ready = []
    app = None

    def on_ready():
        ready.append(app.screen_instance)

    app = ProgressApp(1, 1, lambda: None, on_ready)

    async def scenario(app, pilot):
        await pilot.pause()
        assert len(ready) == 1

    asyncio.run(_run(app, scenario))


def test_final_report_shows_result_counts_without_candidate_values():
    from types import SimpleNamespace

    app = ProgressApp(3, 1, lambda: None)

    async def scenario(app, pilot):
        await pilot.pause()
        screen = app.screen_instance
        assert screen is not None
        results = [
            SimpleNamespace(classification=SimpleNamespace(
                result=SimpleNamespace(value="AUTHENTICATION_FAILED")
            )),
            SimpleNamespace(classification=SimpleNamespace(
                result=SimpleNamespace(value="INCONCLUSIVE")
            )),
        ]
        screen.set_results(results)
        summary = screen.query_one("#summary", Static).render().plain
        assert "Processed: 2 / 3" in summary
        assert "AUTHENTICATION_FAILED: 1" in summary
        assert "INCONCLUSIVE: 1" in summary

    asyncio.run(_run(app, scenario))
