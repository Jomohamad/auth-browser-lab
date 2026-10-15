# Signed by JOE
"""Tests for CLI command behavior: help completeness, version, doctor,
check-updates (read-only), settings (no browser), invalid combinations, and
config rejection for denied hosts."""

import json

import pytest

from auth_audit import cli, settings_tui, dependency_manager as dm


class TestHelpAndVersion:
    def test_help_lists_all_commands(self):
        text = cli.build_parser().format_help()
        for token in (
            "--settings", "--doctor", "--check-updates", "--update-deps",
            "--version", "--config", "--headless", "--create-example-config",
            "--create-example-password", "--always-on-top",
        ):
            assert token in text, f"help missing {token}"

    def test_help_has_examples_and_exit_codes(self):
        text = cli.build_parser().format_help()
        # Help is intentionally minimal: options only, no prose sections.
        assert "Examples" not in text
        assert "Exit codes" not in text
        assert "Precedence" not in text
        assert "Safe execution" not in text
        assert "Troubleshooting" not in text

    def test_version(self, capsys):
        rc = cli.main(["--version"])
        assert rc == 0
        assert "1.1.0" in capsys.readouterr().out


class TestDoctor:
    def _report(self, network_ok=True):
        entry = dm.DependencyStatus(
            name="playwright", kind="python", required=True,
            installed="1.64.0", latest="1.64.0", up_to_date=True, checked=network_ok,
        )
        return dm.EnvironmentReport(
            python_ok=True, python_version="3.14.7", min_python="3.10",
            network_checked=True, network_ok=network_ok, entries=[entry],
        )

    def test_doctor_ok(self, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "target_url": "http://127.0.0.1:8765/login",
            "allowed_hosts": ["127.0.0.1"],
        }), encoding="utf-8")
        monkeypatch.setattr(dm, "check_updates", lambda: self._report())
        rc = cli.cmd_doctor(str(cfg))
        assert rc == 0
        out = capsys.readouterr().out
        assert "good" in out.lower()

    def test_doctor_reports_offline_skipped(self, tmp_path, monkeypatch, capsys):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "target_url": "http://127.0.0.1:8765/login",
            "allowed_hosts": ["127.0.0.1"],
        }), encoding="utf-8")
        monkeypatch.setattr(dm, "check_updates", lambda: self._report(network_ok=False))
        rc = cli.cmd_doctor(str(cfg))
        out = capsys.readouterr().out
        assert "offline" in out.lower()
        assert rc in (0, 1)


class TestCheckUpdates:
    def test_offline_message(self, monkeypatch, capsys):
        report = dm.EnvironmentReport(
            python_ok=True, python_version="3.14", min_python="3.10",
            network_checked=True, network_ok=False, entries=[],
        )
        monkeypatch.setattr(dm, "check_updates", lambda: report)
        rc = cli.cmd_check_updates()
        out = capsys.readouterr().out
        assert "offline" in out.lower()
        assert "not confirmation" in out.lower()
        assert rc == 0


class TestSettingsNoBrowser:
    def test_settings_launches_without_browser(self, monkeypatch):
        called = {"n": 0}

        def fake_launch(config_path):
            called["n"] += 1
            return 0

        monkeypatch.setattr(settings_tui, "launch_settings", fake_launch)
        rc = cli.main(["--settings"])
        assert rc == 0
        assert called["n"] == 1


class TestInvalidCombination:
    def test_password_with_settings_rejected(self):
        rc = cli.main(["--settings", "--password", "secret"])
        assert rc == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
