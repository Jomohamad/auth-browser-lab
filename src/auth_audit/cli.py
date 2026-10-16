# Signed by JOE
"""Command-line interface for the auth testing tool.

Commands (``python tester.py --help`` for the full page):
    --settings        Launch the interactive settings TUI (no browser).
    --version         Print the application version.
    --doctor          Run environment/config diagnostics (no changes).
    --config PATH     Choose the configuration file (default: config.json).
    --check-updates   Report installed vs latest compatible versions (read-only).
    --update-deps     Interactively update declared dependencies (confirmed).
    --headless        Force headless browser for this run.
    --username/--password/--password-file/--create-example-* : run options.

Precedence (highest first): CLI options > environment variables > config file.
Exit codes: 0 ok, 1 config/usage error, 2 run error, 3 security stop, 130 Ctrl-C.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

# Package version is the single source of truth.
try:  # pragma: no cover - trivial
    from . import __version__ as APP_VERSION
except Exception:  # noqa: BLE001
    APP_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Styled output helpers (Rich if available, else plain text).
# ---------------------------------------------------------------------------

def _print(msg: str) -> None:
    try:
        from rich.console import Console

        Console().print(msg)
    except Exception:  # noqa: BLE001 - keep working without Rich
        print(msg)


def _info(msg: str) -> None:
    _print(f"[bold cyan][INFO][/bold cyan] {msg}")


def _ok(msg: str) -> None:
    _print(f"[bold green][ OK ][/bold green] {msg}")


def _warn(msg: str) -> None:
    _print(f"[bold yellow][WARN][/bold yellow] {msg}")


def _err(msg: str) -> None:
    _print(f"[bold red][FAIL][/bold red] {msg}")


# ---------------------------------------------------------------------------
# Argument parser.
# ---------------------------------------------------------------------------

class _NoUsageFormatter(argparse.RawDescriptionHelpFormatter):
    """Help formatter that suppresses the auto-generated 'usage:' line."""

    def add_usage(self, usage, actions, groups, prefix=None):  # noqa: D401
        return

    def format_usage(self):  # noqa: D401
        return ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tester.py",
        formatter_class=_NoUsageFormatter,
        add_help=True,
    )
    parser.add_argument("--version", action="store_true",
                        help="Show the application version and exit.")
    parser.add_argument("--settings", action="store_true",
                        help="Launch the interactive settings TUI (no browser).")
    parser.add_argument("--doctor", action="store_true",
                        help="Run environment/configuration diagnostics and exit "
                             "(makes no changes).")
    parser.add_argument("--config", "-c", default=None,
                        help="Path to the configuration JSON file "
                             "(required to run a test; default: config.json).")
    parser.add_argument("--check-updates", action="store_true",
                        help="Report installed vs latest compatible versions "
                             "(read-only; installs nothing).")
    parser.add_argument("--update-deps", action="store_true",
                        help="Interactively update declared dependencies after "
                             "confirmation (never silent).")
    parser.add_argument("--yes", action="store_true",
                        help="Assume 'yes' for the dependency-update confirmation.")
    parser.add_argument("--exclude-breaking", action="store_true",
                        help="With --update-deps, skip MAJOR version bumps.")

    # Run options
    parser.add_argument("--headless", action="store_true",
                        help="Force headless browser for this run.")
    parser.add_argument("--concurrent-windows", type=int, default=None,
                        help="Number of concurrent browser windows "
                             "(overrides config; default from settings).")
    parser.add_argument("--no-resume", action="store_true",
                        help="Disable resume-on-stop; start from entry 1.")
    parser.add_argument("--username", help="Override the test username "
                                           "(also set via AUTH_TEST_USERNAME).")
    parser.add_argument("--password-file", "-p",
                        help="Override the password file path from config.")
    parser.add_argument("--password", help="Provide a single synthetic test "
                                           "password at run time (functional "
                                           "check). Prefer env/Credential Manager.")
    parser.add_argument("--prompt-password", action="store_true",
                        help="Prompt for the single synthetic test password.")
    parser.add_argument("--always-on-top", dest="always_on_top",
                        action="store_true", default=None,
                        help="Attempt Windows console always-on-top for this run.")
    parser.add_argument("--no-always-on-top", dest="always_on_top",
                        action="store_false",
                        help="Disable console always-on-top for this run.")

    # Example file creation
    parser.add_argument("--create-example-config", action="store_true",
                        help="Create an example configuration file and exit.")
    parser.add_argument("--create-example-password", action="store_true",
                        help="Create an example password file and exit.")
    parser.add_argument("--example-config-name", default="config.example.json",
                        help="Name for the example config file.")
    parser.add_argument("--example-password-name", default="password.txt.example",
                        help="Name for the example password file.")

    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose error output (tracebacks).")
    return parser


def _validate_combinations(args: argparse.Namespace) -> Optional[str]:
    """Return an error string for an invalid argument combination."""
    if args.update_deps and not args.check_updates and args.headless:
        # --headless is meaningless for a dependency update but not fatal.
        pass
    if (args.password or args.prompt_password) and (args.settings or args.doctor
                                                    or args.check_updates
                                                    or args.update_deps):
        return ("A runtime password can only be supplied with a test run, "
                "not with --settings/--doctor/--check-updates/--update-deps.")
    return None


# ---------------------------------------------------------------------------
# Command handlers.
# ---------------------------------------------------------------------------

def cmd_version() -> int:
    _info(f"Authentication Testing Tool v{APP_VERSION}")
    return 0


def cmd_create_examples(args: argparse.Namespace) -> Optional[int]:
    from .config import create_example_config
    from .password_handler import create_example_password_file

    handled = False
    if args.create_example_config:
        out = Path(args.example_config_name)
        create_example_config(out)
        _ok(f"Example configuration created: {out}")
        handled = True
    if args.create_example_password:
        out = Path(args.example_password_name)
        create_example_password_file(out)
        _ok(f"Example password file created: {out}")
        handled = True
    return 0 if handled else None


def cmd_doctor(config_path: str) -> int:
    from .dependency_manager import check_updates
    from . import schema

    ok_overall = True
    _info("Environment diagnostics\n")

    report = check_updates()
    _print(
        f"[bold]{'Python ' + report.python_version}[/bold] "
        f"(requires >= {report.min_python}): "
        + _pass_fail(report.python_ok)
    )
    ok_overall &= report.python_ok

    if report.network_ok:
        _ok("Remote package registry reachable.")
    else:
        _warn("Remote version check unavailable (offline); versions shown as "
              "skipped — this is NOT confirmation that packages are up to date.")

    _print("\nDependencies / tools:")
    for e in report.entries:
        state = _dependency_state(e)
        extra = ""
        if e.compatibility_note:
            extra = f"  — {e.compatibility_note}"
        _print(f"  [dim]{e.kind:<16}[/dim] {e.name:<18} {state}{extra}")
        if e.required and e.kind == "python" and not e.installed:
            ok_overall = False

    # Configuration validity.
    try:
        from .config import load_config, ConfigError, load_raw_config

        raw = load_raw_config(config_path)
        good, errors = schema.validate_config(raw)
        _print("")
        if good:
            # Also ensure it fully constructs (allowlist/HTTPS/denylist).
            try:
                cfg = load_config(config_path)
                _ok(f"Configuration valid: {config_path} "
                    f"(target host: {cfg.target_hostname or '?'})")
            except ConfigError as e:
                _err(f"Configuration invalid: {e}")
                ok_overall = False
        else:
            _err(f"Configuration has {len(errors)} problem(s):")
            for msg in errors:
                _print(f"    - {msg}")
            ok_overall = False
    except Exception as e:  # noqa: BLE001
        _err(f"Could not read configuration '{config_path}': {e}")
        ok_overall = False

    _print("")
    if ok_overall:
        _ok("Doctor: environment looks good.")
        return 0
    _warn("Doctor: one or more checks need attention (see above).")
    return 1


def _pass_fail(ok: bool) -> str:
    return "[green]PASS[/green]" if ok else "[red]FAIL[/red]"


def _dependency_state(e) -> str:
    if e.offline:
        return "skipped (offline)"
    if e.kind == "python":
        inst = e.installed or "missing"
        if e.installed is None:
            return f"[red]{inst}[/red] (required={e.required})"
        if e.update_available:
            return f"[yellow]{inst}[/yellow] -> [cyan]{e.latest}[/cyan] (update)"
        return f"[green]{inst}[/green] (up to date)"
    if e.kind == "playwright-br":
        return ("[green]installed[/green]" if e.up_to_date
                else "[red]missing[/red]")
    return ("[green]found[/green]" if e.installed else "[dim]not found[/dim]")


def cmd_check_updates() -> int:
    from .dependency_manager import check_updates

    report = check_updates()

    if not report.network_ok:
        _warn("Remote version check unavailable (offline). Version comparison "
              "was skipped — this is not confirmation that packages are current.")
    else:
        _ok("Remote package registry reachable.")

    counts = report.summary_counts()
    any_update = False
    _info("Installed vs latest-compatible versions\n")
    for e in report.entries:
        req = "required" if e.required else "optional"
        if e.kind == "python":
            if e.offline:
                line = (f"  {e.name:<18} {e.installed or 'missing':<12} "
                        f"latest: (offline)   [{req}]")
            elif e.installed is None:
                line = (f"  {e.name:<18} {'missing':<12} latest: {e.latest or '?':<12} "
                        f"[{req}] NOT INSTALLED")
            elif e.update_available:
                any_update = True
                line = (f"  {e.name:<18} {e.installed:<12} -> {e.latest:<12} "
                        f"[{req}] UPDATE AVAILABLE")
            else:
                line = (f"  {e.name:<18} {e.installed:<12} latest: {e.latest or '?':<12} "
                        f"[{req}] up to date")
        elif e.kind == "playwright-br":
            line = (f"  {e.name:<18} {'(browser)':<12} "
                    f"{'installed' if e.up_to_date else 'missing':<12} [{req}]")
        else:
            line = (f"  {e.name:<18} {'(tool)':<12} "
                    f"{(e.installed or 'not found'):<12} [{req}]")
        _print(line)
        if e.compatibility_note:
            _print(f"      [dim]compat: {e.compatibility_note}[/dim]")
            _print(f"      [dim]apply : {e.recommended_command}[/dim]")

    _print(f"\nOutdated: {counts['outdated']}  "
           f"Missing required: {counts['missing_required']}")
    if counts["outdated"]:
        _info("Apply with: python tester.py --update-deps  (confirmation required)")
    return 0


def cmd_update_deps(args: argparse.Namespace) -> int:
    from . import dependency_manager as dm

    report = dm.check_updates()
    if not report.network_ok:
        _warn("Offline: cannot resolve compatible updates now. Nothing changed.")
        return 1

    result = dm.update_dependencies(
        report,
        assume_yes=args.yes,
        exclude_breaking=args.exclude_breaking,
        project_root=Path(__file__).resolve().parents[2],
    )
    if result["cancelled"]:
        _warn("Dependency update cancelled; nothing changed.")
        return 0
    if result["errors"] == ["No updates available."]:
        _ok("All declared dependencies are already at the latest compatible version.")
        return 0
    if result["snapshot"]:
        _info(f"Version snapshot written: {result['snapshot']}")
    for pkg in result["updated"]:
        _ok(f"Updated {pkg}")
    if result["playwright_browsers"]:
        _warn("Playwright browsers update separately — review, then run: "
              "python -m playwright install chromium")
    for e in result["errors"]:
        _err(e)
    _print("Verified installed: " + (", ".join(result["verified"]) or "(none)"))
    return 1 if result["errors"] else 0


def cmd_settings(config_path: str) -> int:
    from . import settings_tui

    return settings_tui.launch_settings(config_path)


def cmd_run(args: argparse.Namespace) -> int:
    from .config import load_config, ConfigError
    from . import windows_console
    from . import credentials
    from .auth_flow import AuthTester
    from .password_handler import (
        PasswordFileError,
        PasswordFileResult,
        read_password_file,
    )
    from .tui.progress import ProgressApp

    # 1. Load + validate configuration.
    try:
        config = load_config(args.config)
    except ConfigError as e:
        _err(f"Configuration error: {e}")
        _info("Run --doctor for details, or --create-example-config for a template.")
        return 1
    except Exception as e:  # noqa: BLE001
        _err(f"Failed to load configuration: {e}")
        return 1

    # 2. Apply CLI/env overrides (CLI > env > config already handled in loader).
    if args.headless:
        config.browser.headless = True
    if args.username:
        config.auth.username = args.username
    elif not config.auth.username:
        config.auth.username = credentials.resolve_username(config.auth.username)
    if args.password_file:
        config.password_file = args.password_file
    if args.concurrent_windows is not None:
        config.browser.concurrent_windows = args.concurrent_windows
    if args.no_resume:
        config.resume_enabled = False
    if args.always_on_top is not None:
        config.always_on_top = args.always_on_top

    # 3. Resolve a single runtime credential ONLY when explicitly requested.
    override_password: Optional[str] = None
    if args.password:
        override_password = args.password
    elif args.prompt_password:
        override_password = credentials.resolve_password(prompt_ok=True)

    # 4. Read password file to get total count for the TUI.
    if override_password is not None:
        passwords_info = PasswordFileResult(
            passwords=[override_password],
            count=1,
            source_path="<provided-at-runtime>",
        )
    else:
        try:
            passwords_info = read_password_file(config.password_file)
        except PasswordFileError as e:
            _err(f"Password file error: {e}")
            return 1
    total_entries = passwords_info.count

    num_windows = min(config.browser.concurrent_windows, total_entries, 100)

    # 5. Optional Windows console always-on-top (warning if it fails).
    if config.always_on_top:
        res = windows_console.maybe_enable(True)
        if res.enabled:
            _ok("Console always-on-top enabled.")
        else:
            _warn(f"Always-on-top not enabled: {res.reason}")

    # 6. Show a concise (secret-free) summary.
    _print("")
    _info(f"Target host : {config.target_hostname}")
    _info(f"Provider    : {config.auth.provider.value}")
    _info(f"Password file / credential : "
          f"{'<runtime credential>' if override_password else config.password_file}")
    _info(f"Concurrent windows : {num_windows}")
    _print("")

    # 7. Run under the progress TUI.
    import threading

    results_container: list = []
    run_errors: list[str] = []
    test_thread = None
    tester = AuthTester(config)

    def on_stop() -> None:
        tester._stop_requested = True

    def progress_callback(
        window_idx: int, completed: int, total: int,
        result_str: str, ms: int,
    ) -> None:
        app.update_progress(window_idx, completed, total, result_str, ms)
        if result_str != "starting…":
            app.set_status("Browser tests are running.")

    def run_test() -> None:
        try:
            app.set_status(
                "Loading browser windows; waiting 5 seconds before navigation…"
            )
            results = tester.run(
                passwords_info,
                progress_callback=progress_callback,
                ui_mode=True,
                startup_delay_seconds=5,
            )
            results_container.extend(results)
            if app.is_running:
                app.set_results(results)
                app.set_status("Testing complete.")
        except Exception as e:  # noqa: BLE001
            run_errors.append(str(e))
            if app.is_running:
                app.set_status(f"Error: {e}")

    def start_test() -> None:
        nonlocal test_thread
        test_thread = threading.Thread(target=run_test, daemon=True)
        test_thread.start()

    app = ProgressApp(
        total_entries, num_windows, on_stop,
        on_ready=start_test,
    )

    try:
        app.run()
    except KeyboardInterrupt:
        tester._stop_requested = True
    if test_thread is not None:
        test_thread.join()

    if run_errors:
        return 2

    results = results_container

    # 8. Exit code mapping.
    from .result_classifier import AuthenticationResult

    has_security_stop = any(
        r.classification.result.value.startswith("STOPPED_") for r in results
    )
    has_errors = any(
        r.classification.result.value in ("CONFIGURATION_ERROR", "NAVIGATION_ERROR")
        for r in results
    )
    if has_errors:
        return 2
    if has_security_stop:
        return 3
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    # Best-effort: prefer UTF-8 output where supported.
    try:  # pragma: no cover
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    parser = build_parser()
    args = parser.parse_args(argv)

    combo_error = _validate_combinations(args)
    if combo_error:
        _err(combo_error)
        return 1

    # --config defaults to None so we can tell whether the user explicitly
    # provided one. When absent, fall back to config.json for commands that
    # need a config file.
    config_explicitly_given = args.config is not None
    config_path = args.config or "config.json"

    action_flags = (
        args.version,
        args.settings,
        args.doctor,
        args.check_updates,
        args.update_deps,
        args.create_example_config,
        args.create_example_password,
    )

    if args.version:
        return cmd_version()

    example_rc = cmd_create_examples(args)
    if example_rc is not None:
        return example_rc

    if args.settings:
        return cmd_settings(config_path)

    if args.doctor:
        return cmd_doctor(config_path)

    if args.check_updates:
        return cmd_check_updates()

    if args.update_deps:
        return cmd_update_deps(args)

    # No command flag given: run the authentication workflow against the
    # default config.json (operator must explicitly run this against an
    # authorized target).
    args.config = config_path
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
