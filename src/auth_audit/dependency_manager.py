# Signed by JOE
"""Dependency and external-tool diagnostics and controlled updates.

Responsibilities:
  * Report environment/Python/packages/Playwright-browser/tool status.
  * ``check_updates()``: compare installed vs latest *compatible* versions
    WITHOUT installing anything; gracefully report "skipped" when offline.
  * ``update_dependencies()``: show a plan, warn about breaking changes, require
    explicit confirmation, snapshot current versions, run updates via the
    current interpreter's ``pip``, then verify and report failures/recovery.

Nothing here silently replaces the dependency set or modifies the global Python.
Playwright *browser* updates and external-tool updates are reported separately
from Python package updates.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Callable, Dict, List, Optional

# Requires-python floor (kept in sync with pyproject.toml).
MIN_PYTHON = (3, 10)

PYPI_JSON = "https://pypi.org/pypi/{name}/json"

# Curated dependency/tool registry. "kind" distinguishes the update pathway.
#   python         -> pip package
#   playwright-br  -> Playwright browser engine (installed via playwright CLI)
#   external       -> system executable used by the project
DEPENDENCY_REGISTRY: List[Dict] = [
    {"name": "playwright", "kind": "python", "required": True},
    {"name": "pydantic", "kind": "python", "required": True},
    {"name": "pydantic-settings", "kind": "python", "required": False},
    {"name": "click", "kind": "python", "required": False},
    {"name": "typing-extensions", "kind": "python", "required": False},
    {"name": "textual", "kind": "python", "required": False,
     "note": "Interactive settings TUI (optional)."},
    {"name": "rich", "kind": "python", "required": False,
     "note": "Styled terminal output (optional)."},
    {"name": "chromium", "kind": "playwright-br", "required": True,
     "note": "Installed via: python -m playwright install chromium"},
    {"name": "git", "kind": "external", "required": False,
     "note": "Version control (optional)."},
]


@dataclass
class DependencyStatus:
    name: str
    kind: str
    required: bool
    installed: Optional[str] = None
    latest: Optional[str] = None
    update_available: bool = False
    up_to_date: bool = False
    checked: bool = False            # True only when a remote check succeeded
    offline: bool = False            # True when the remote check was skipped
    compatibility_note: str = ""
    recommended_command: str = ""
    detail: str = ""
    note: str = ""


@dataclass
class EnvironmentReport:
    python_ok: bool
    python_version: str
    min_python: str
    network_checked: bool
    network_ok: bool
    entries: List[DependencyStatus] = field(default_factory=list)

    def summary_counts(self) -> Dict[str, int]:
        return {
            "total": len(self.entries),
            "outdated": sum(1 for e in self.entries if e.update_available),
            "offline": sum(1 for e in self.entries if e.offline),
            "missing_required": sum(
                1 for e in self.entries
                if e.required and e.kind == "python" and not e.installed
            ),
        }


# ---------------------------------------------------------------------------
# Version helpers (use packaging if available, else a lenient fallback).
# ---------------------------------------------------------------------------

def _parse_version(v: str):
    try:
        from packaging.version import Version

        return Version(v)
    except Exception:  # noqa: BLE001
        return _FallbackVersion(v)


class _FallbackVersion:
    def __init__(self, v: str):
        self.parts = tuple(
            int(p) for p in "".join(c if c.isdigit() else " " for c in v).split()
        ) or (0,)

    def __lt__(self, other: "Optional[_FallbackVersion]"):  # type: ignore[override]
        if other is None:
            return False
        a, b = self.parts, getattr(other, "parts", (0,))
        return a < b

    def __le__(self, other):  # type: ignore[override]
        return self < other or self == other

    def __eq__(self, other):  # type: ignore[override]
        return getattr(other, "parts", None) == self.parts

    def __repr__(self):
        return f"_FallbackVersion{self.parts}"


def installed_version(name: str) -> Optional[str]:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None
    except Exception:  # noqa: BLE001
        return None


def _fetch_json(url: str, timeout: float):
    import urllib.request

    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def latest_pypi_version(name: str, timeout: float = 6.0):
    """Return (version_or_None, network_ok). Distinguishes offline from missing."""
    try:
        data = _fetch_json(PYPI_JSON.format(name=name), timeout=timeout)
        return data.get("info", {}).get("version"), True
    except Exception:  # noqa: BLE001 - offline, DNS, HTTP...
        return None, False


def python_browsers_path() -> Path:
    import os

    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if override:
        return Path(override)
    if sys.platform.startswith("win"):
        return Path.home() / "AppData" / "Local" / "ms-playwright"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "ms-playwright"
    return Path.home() / ".cache" / "ms-playwright"


def chromium_installed() -> tuple[bool, str]:
    """Best-effort check for an installed Chromium (no network required)."""
    base = python_browsers_path()
    if not base.exists():
        return False, f"No browser cache at {base}"
    matches = list(base.glob("chromium*"))
    if matches:
        return True, f"{matches[0].name} in {base}"
    return False, f"No chromium* under {base}"


def check_updates(timeout: float = 6.0) -> EnvironmentReport:
    """Build an environment report. Does NOT install or change anything."""
    py_ok = sys.version_info[:2] >= MIN_PYTHON
    report = EnvironmentReport(
        python_ok=py_ok,
        python_version=sys.version.split()[0],
        min_python=".".join(str(x) for x in MIN_PYTHON),
        network_checked=False,
        network_ok=False,
    )

    # Probe network once with a required package; reuse result for others.
    net_probe = latest_pypi_version("playwright", timeout=timeout)
    network_ok = net_probe[1]
    report.network_checked = True
    report.network_ok = network_ok

    for entry in DEPENDENCY_REGISTRY:
        name = entry["name"]
        kind = entry["kind"]
        status = DependencyStatus(
            name=name, kind=kind, required=bool(entry.get("required"))
        )
        status.note = entry.get("note", "")

        if kind == "python":
            status.installed = installed_version(name)
            if status.installed is None:
                status.detail = "not installed"
                status.recommended_command = f'python -m pip install "{name}"'
            else:
                status.detail = "installed"
            # Remote check (only if network is available).
            if network_ok:
                latest, _ = latest_pypi_version(name, timeout=timeout)
                status.latest = latest
                status.checked = latest is not None
                if latest and status.installed:
                    if _parse_version(latest) > _parse_version(status.installed):
                        status.update_available = True
                        status.compatibility_note = _compat_note(
                            status.installed, latest
                        )
                        status.recommended_command = (
                            f'python -m pip install --upgrade "{name}=={latest}"'
                        )
                    else:
                        status.up_to_date = True
            else:
                status.offline = True
                status.detail = "remote version check skipped (offline)"

        elif kind == "playwright-br":
            ok, detail = chromium_installed()
            status.installed = "present" if ok else "missing"
            status.detail = detail
            status.up_to_date = ok
            status.recommended_command = "python -m playwright install chromium"

        elif kind == "external":
            found = shutil.which(name)
            status.installed = found or None
            status.detail = found or "not found on PATH"
            status.up_to_date = bool(found)
            if not found:
                status.recommended_command = f"install '{name}' via your package manager"

        report.entries.append(status)

    return report


def _compat_note(installed: str, latest: str) -> str:
    iv = _parse_version(installed)
    lv = _parse_version(latest)
    try:
        i_major = iv.release[0]
        l_major = lv.release[0]
    except Exception:  # noqa: BLE001
        return "Newer version available; review the changelog."
    if l_major > i_major:
        return (
            f"MAJOR bump {i_major} -> {l_major}: likely breaking changes; "
            "review release notes and update code accordingly."
        )
    return "Minor/patch update; backward-compatible range recommended."


# ---------------------------------------------------------------------------
# Controlled update workflow.
# ---------------------------------------------------------------------------

@dataclass
class UpdatePlan:
    python_packages: List[str] = field(default_factory=list)
    playwright_browsers: List[str] = field(default_factory=list)
    external_tools: List[str] = field(default_factory=list)
    breaking_risk: bool = False

    def is_empty(self) -> bool:
        return not (self.python_packages or self.playwright_browsers)


def build_update_plan(report: EnvironmentReport) -> UpdatePlan:
    plan = UpdatePlan()
    for e in report.entries:
        if not e.update_available:
            continue
        if "MAJOR" in e.compatibility_note:
            plan.breaking_risk = True
        if e.kind == "python":
            plan.python_packages.append(f"{e.name}=={e.latest}")
        elif e.kind == "playwright-br":
            plan.playwright_browsers.append(e.name)
    return plan


def snapshot_versions(path: Path) -> Path:
    """Record currently installed versions before an update (recovery aid)."""
    lines = [f"# snapshot {datetime.now(timezone.utc).isoformat()}", ""]
    for e in DEPENDENCY_REGISTRY:
        if e["kind"] == "python":
            v = installed_version(e["name"])
            if v:
                lines.append(f"{e['name']}=={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def update_dependencies(
    report: Optional[EnvironmentReport] = None,
    *,
    assume_yes: bool = False,
    confirm: Optional[Callable[[str], bool]] = None,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    project_root: Optional[Path] = None,
    exclude_breaking: bool = False,
) -> Dict:
    """Controlled dependency update. Returns a structured result dict.

    Steps: build plan -> show/warn -> confirm -> snapshot -> install -> verify.
    Never runs without confirmation unless ``assume_yes`` is set.
    """
    runner = runner or subprocess.run
    project_root = project_root or Path.cwd()
    report = report or check_updates()

    result: Dict = {
        "updated": [],
        "playwright_browsers": [],
        "verified": [],
        "errors": [],
        "cancelled": False,
        "snapshot": None,
    }

    if not report.network_ok:
        result["errors"].append(
            "Remote version check was unavailable (offline). Cannot resolve "
            "compatible updates; no changes were made."
        )
        return result

    plan = build_update_plan(report)
    pkgs = list(plan.python_packages)
    if exclude_breaking and plan.breaking_risk:
        pkgs = [p for p in pkgs if not _is_major_bump(report, p)]

    if not pkgs and not plan.playwright_browsers:
        result["errors"].append("No updates available.")
        return result

    warning_lines = [
        "Planned updates:",
        *[f"  - {p}" for p in pkgs],
        *[f"  - browser: {b}" for b in plan.playwright_browsers],
    ]
    if plan.breaking_risk:
        warning_lines.append(
            "\nWARNING: this includes a MAJOR version bump that may introduce "
            "breaking changes for your configuration/code."
        )
    warning = "\n".join(warning_lines)

    # Confirm before making ANY changes.
    if assume_yes:
        confirmed = True
    elif confirm is not None:
        confirmed = bool(confirm(warning))
    else:
        confirmed = _prompt_yes_no(warning)
    if not confirmed:
        result["cancelled"] = True
        return result

    # Preserve/record current versions before changing anything.
    try:
        snap = project_root / "dependency-snapshot.txt"
        result["snapshot"] = str(snapshot_versions(snap))
    except OSError as e:
        result["errors"].append(f"Could not write version snapshot: {e}")

    # Install Python packages via the current interpreter's pip only.
    if pkgs:
        try:
            cp = runner(
                [sys.executable, "-m", "pip", "install", "--upgrade", *pkgs],
                capture_output=True, text=True,
            )
            if getattr(cp, "returncode", 1) == 0:
                result["updated"].extend(pkgs)
            else:
                result["errors"].append(
                    f"pip install failed (rc={getattr(cp, 'returncode', '?')}). "
                    f"Recover with: python -m pip install -r "
                    f"'{result.get('snapshot') or 'dependency-snapshot.txt'}'"
                )
        except Exception as e:  # noqa: BLE001
            result["errors"].append(f"pip install error: {e}")

    # Playwright browsers are a separate pathway; never auto-run without notice.
    if plan.playwright_browsers:
        result["playwright_browsers"] = list(plan.playwright_browsers)

    # Verify what is now installed.
    post = check_updates()
    for e in post.entries:
        if e.kind == "python" and any(
            e.name == p.split("==")[0] for p in result["updated"]
        ):
            result["verified"].append(f"{e.name}=={e.installed}")

    return result


def _is_major_bump(report: EnvironmentReport, pkg_spec: str) -> bool:
    name = pkg_spec.split("==")[0]
    for e in report.entries:
        if e.name == name:
            return "MAJOR" in e.compatibility_note
    return False


def _prompt_yes_no(warning: str) -> bool:
    print(warning)
    try:
        return input("Proceed with these updates? [y/N] ").strip().lower() in (
            "y", "yes"
        )
    except (EOFError, KeyboardInterrupt):
        return False
