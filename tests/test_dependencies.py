# Signed by JOE
"""Tests for dependency diagnostics and controlled updates.

External registries and pip are mocked; these tests never touch the network
or install anything.
"""

import subprocess
from unittest.mock import Mock

import pytest

from auth_audit import dependency_manager as dm


def _fresh_report(entries, network_ok=True):
    return dm.EnvironmentReport(
        python_ok=True,
        python_version="3.14.7",
        min_python="3.10",
        network_checked=True,
        network_ok=network_ok,
        entries=entries,
    )


class TestCheckUpdates:
    def test_check_updates_installs_nothing(self, monkeypatch):
        calls = {"install": 0}

        monkeypatch.setattr(
            dm, "latest_pypi_version",
            lambda name, timeout=6.0: ("2.0.0" if name == "playwright" else "1.0.0", True),
        )
        monkeypatch.setattr(dm, "installed_version", lambda name: "1.0.0")
        monkeypatch.setattr(dm, "chromium_installed", lambda: (True, "chromium-1"))
        import shutil

        monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/" + n)

        report = dm.check_updates()
        assert report.network_ok is True
        playwright = next(e for e in report.entries if e.name == "playwright")
        assert playwright.update_available is True
        assert "MAJOR" in playwright.compatibility_note  # 1.x -> 2.x
        assert calls["install"] == 0  # read-only by construction

    def test_offline_reported_as_skipped_not_uptodate(self, monkeypatch):
        monkeypatch.setattr(
            dm, "latest_pypi_version", lambda name, timeout=6.0: (None, False)
        )
        report = dm.check_updates()
        assert report.network_ok is False
        offline = [e for e in report.entries if e.offline]
        assert offline  # at least one entry reports offline
        # Offline entries must NOT be claimed as up-to-date.
        for e in offline:
            assert e.up_to_date is False

    def test_build_update_plan_marks_breaking(self):
        report = _fresh_report([
            dm.DependencyStatus(
                name="playwright", kind="python", required=True,
                installed="1.0.0", latest="2.0.0", update_available=True,
                compatibility_note="MAJOR bump 1 -> 2: breaking",
            )
        ])
        plan = dm.build_update_plan(report)
        assert plan.breaking_risk is True
        assert "playwright==2.0.0" in plan.python_packages


class TestUpdateDependencies:
    def _outdated_report(self):
        return _fresh_report([
            dm.DependencyStatus(
                name="playwright", kind="python", required=True,
                installed="1.0.0", latest="2.0.0", update_available=True,
                checked=True,
                compatibility_note="MAJOR bump 1 -> 2: breaking",
                recommended_command="pip install playwright==2.0.0",
            )
        ])

    def test_cancel_does_not_install(self):
        report = self._outdated_report()
        runner = Mock()
        result = dm.update_dependencies(
            report, assume_yes=False, confirm=lambda msg: False, runner=runner
        )
        assert result["cancelled"] is True
        runner.assert_not_called()

    def test_confirm_then_install_and_verify(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dm, "installed_version", lambda name: "2.0.0")
        # After "install", the verification pass reports it installed.
        monkeypatch.setattr(dm, "check_updates", lambda: self._outdated_report())

        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        report = self._outdated_report()
        result = dm.update_dependencies(
            report, assume_yes=True, runner=runner, project_root=tmp_path
        )
        runner.assert_called_once()
        args = runner.call_args[0][0]
        assert args[1] == "-m" and "pip" in args and "playwright==2.0.0" in args
        assert "playwright==2.0.0" in result["updated"]
        assert result["snapshot"] and (tmp_path / "dependency-snapshot.txt").exists()

    def test_offline_update_refuses_without_network(self):
        report = _fresh_report([], network_ok=False)
        runner = Mock()
        result = dm.update_dependencies(
            report, assume_yes=True, runner=runner
        )
        assert result["errors"]
        assert "offline" in result["errors"][0].lower()
        runner.assert_not_called()

    def test_exclude_breaking(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dm, "installed_version", lambda name: "1.0.0")
        monkeypatch.setattr(dm, "check_updates", lambda: self._outdated_report())
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        report = self._outdated_report()
        result = dm.update_dependencies(
            report, assume_yes=True, runner=runner,
            project_root=tmp_path, exclude_breaking=True,
        )
        # MAJOR bump excluded -> nothing left to install.
        assert result["updated"] == []
        assert result["errors"] and "No updates" in result["errors"][0]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
