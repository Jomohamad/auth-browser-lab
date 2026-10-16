# Signed by JOE
"""Declarative configuration schema for the settings TUI and CLI.

This module is the single source of truth describing *every* supported
configuration field: its page/group, type, choices, default, description, and
whether it is a secret. It lets:

  * the interactive settings TUI render/edit/validate every field,
  * the CLI ``--doctor`` / config editor validate a raw config dict,
  * configuration be persisted atomically, with backups, and never leaking a
    secret into the JSON file.

It is intentionally free of any TUI/dependency imports so it is fast to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import (
    AppConfig,
    AuthenticationProvider,
    BrowserType,
    backup_config,
    load_raw_config,
    write_config_atomic,
)
from pydantic import ValidationError


# Field type tokens used by the editor.
class FieldType:
    STR = "str"
    BOOL = "bool"
    INT = "int"
    FLOAT = "float"
    STRLIST = "strlist"
    ENUM = "enum"


@dataclass(frozen=True)
class SettingSpec:
    """Description of a single configuration field."""
    path: str                     # dotted, e.g. "auth.provider" or "target_url"
    label: str
    group: str                    # TUI page id
    type: str
    default: Any
    description: str = ""
    choices: Tuple[str, ...] = ()
    secret: bool = False          # mask input; never echo
    persist: bool = True          # write to JSON (secrets are not persisted)
    required: bool = False
    min: Optional[float] = None
    max: Optional[float] = None
    help_text: str = ""          # contextual help shown in the TUI


# Ordered page list. Keys are stable ids used by the TUI.
PAGES: List[Dict[str, str]] = [
    {"id": "overview", "title": "Overview", "icon": "⛭"},
    {"id": "target", "title": "Target", "icon": "⌂"},
    {"id": "auth", "title": "Authentication", "icon": "⚿"},
    {"id": "credentials", "title": "Test Account", "icon": "⚿"},
    {"id": "browser", "title": "Browser", "icon": "▣"},
    {"id": "execution", "title": "Execution", "icon": "▶"},
    {"id": "reporting", "title": "Reporting", "icon": "≡"},
    {"id": "security", "title": "Advanced (Security)", "icon": "⛨"},
    {"id": "dependencies", "title": "Dependencies", "icon": "⛭"},
]

_PROVIDER_CHOICES = tuple(p.value for p in AuthenticationProvider)
_BROWSER_CHOICES = tuple(b.value for b in BrowserType)
_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
_VERBOSITY = ("minimal", "normal", "verbose")


def _specs() -> List[SettingSpec]:
    return [
        # --- Page 2: Target ------------------------------------------------
        SettingSpec(
            "target_url", "Target login URL", "target", FieldType.STR,
            "http://127.0.0.1:8765/login", required=True,
            description="Login page URL. HTTPS required for non-local hosts.",
            help_text="Must be in allowed_hosts. Public domains are allowed "
                      "once allowlisted.",
        ),
        SettingSpec(
            "allowed_hosts", "Allowed hosts", "target", FieldType.STRLIST,
            ["127.0.0.1", "localhost"],
            description="Hosts you are authorized to test (one per line).",
        ),

        # --- Page 3: Authentication ---------------------------------------
        SettingSpec(
            "auth.provider", "Provider", "auth", FieldType.ENUM,
            "custom", choices=_PROVIDER_CHOICES,
            description="Authentication provider shape/flow.",
        ),
        SettingSpec(
            "auth.username", "Username / email", "auth", FieldType.STR, "",
            description="Dedicated test-account identifier (non-secret).",
        ),
        SettingSpec(
            "auth.username_selector", "Username selector", "auth",
            FieldType.STR, "#username",
            description="CSS selector for the username/email field.",
        ),
        SettingSpec(
            "auth.password_selector", "Password selector", "auth",
            FieldType.STR, "#password",
            description="CSS selector for the password field.",
        ),
        SettingSpec(
            "auth.submit_selector", "Submit selector", "auth",
            FieldType.STR, "button[type=\"submit\"]",
            description="CSS selector for the submit/login button.",
        ),
        SettingSpec(
            "auth.success_url_patterns", "Success URL patterns", "auth",
            FieldType.STRLIST, ["/app/dashboard"],
            description="Post-login URL paths that confirm success.",
        ),
        SettingSpec(
            "auth.success_selectors", "Success selectors", "auth",
            FieldType.STRLIST, ["[data-testid=\"user-menu\"]"],
            description="CSS selectors that only exist when authenticated.",
        ),
        SettingSpec(
            "auth.failure_selectors", "Failure selectors", "auth",
            FieldType.STRLIST, ["[data-testid=\"login-error\"]"],
            description="CSS selectors for login error messages.",
        ),
        SettingSpec(
            "auth.success_on_navigation_without_failure",
            "Success on navigation w/o failure", "auth", FieldType.BOOL, False,
            description="Operator-defined success when the page navigates off "
                        "the login page and shows no failure element.",
        ),

        # --- Page 4: Test Account (secrets, not persisted) ----------------
        SettingSpec(
            "auth.password", "Password (optional)", "credentials",
            FieldType.STR, "", secret=True, persist=False,
            description="Never written to the JSON config. Resolved at runtime "
                        "from env / Credential Manager / prompt.",
            help_text="This value is masked and is stored only in the secure "
                      "credential store, never in config.json.",
        ),

        # --- Page 5: Browser ----------------------------------------------
        SettingSpec(
            "browser.browser", "Browser engine", "browser", FieldType.ENUM,
            "chromium", choices=_BROWSER_CHOICES,
            description="Browser engine to launch.",
        ),
        SettingSpec(
            "browser.headless", "Headless", "browser", FieldType.BOOL, False,
            description="Run the browser headless.",
        ),
        SettingSpec(
            "browser.viewport_width", "Viewport width", "browser",
            FieldType.INT, 1280, min=200, max=10000,
            description="Viewport width in pixels.",
        ),
        SettingSpec(
            "browser.viewport_height", "Viewport height", "browser",
            FieldType.INT, 720, min=200, max=10000,
            description="Viewport height in pixels.",
        ),
        SettingSpec(
            "browser.navigation_timeout_ms", "Navigation timeout (ms)",
            "browser", FieldType.INT, 15000, min=500, max=120000,
            description="Navigation timeout in milliseconds.",
        ),
        SettingSpec(
            "browser.delay_before_submit_seconds", "Delay before submit (s)",
            "browser", FieldType.FLOAT, 1.0, min=0, max=60,
            description="Delay before submitting the login form.",
        ),
        SettingSpec(
            "browser.inter_entry_delay_seconds", "Delay between entries (s)",
            "browser", FieldType.FLOAT, 0.0, min=0, max=60,
            description="Pacing delay between candidate entries (mock runs).",
        ),
        SettingSpec(
            "always_on_top", "Console always-on-top", "browser",
            FieldType.BOOL, False,
            description="Best-effort Windows console always-on-top.",
            help_text="Windows only; silently ignored elsewhere. Never steals "
                      "focus or moves/resizes the window without approval.",
        ),
        SettingSpec(
            "browser.concurrent_windows", "Concurrent windows", "browser",
            FieldType.INT, 6, min=1, max=100,
            description="Number of browser windows running in parallel.",
            help_text="Higher = faster testing but more load on the target. "
                      "Default 6. Maximum 100.",
        ),

        # --- Page 6: Execution --------------------------------------------
        SettingSpec(
            "stop_on_security_challenge", "Stop on security challenge",
            "execution", FieldType.BOOL, True,
            description="Stop immediately when a challenge is detected.",
        ),
        SettingSpec(
            "resume_enabled", "Resume on next run", "execution",
            FieldType.BOOL, True,
            description="Save last tried password so the next run continues from it.",
            help_text="When you stop testing (Ctrl+C), the last completed entry "
                      "is saved. The next run starts from the following entry.",
        ),
        SettingSpec(
            "resume_state_file", "Resume state file", "execution",
            FieldType.STR, ".auth_resume_state.json",
            description="File that stores resume progress.",
            help_text="Contains the last completed entry index, password file, "
                      "and target URL.",
        ),
        SettingSpec(
            "password_file", "Password file", "execution", FieldType.STR,
            "password.txt",
            description="Candidate password list (gitignored).",
        ),

        # --- Page 7: Reporting --------------------------------------------
        SettingSpec(
            "report.report_directory", "Report directory", "reporting",
            FieldType.STR, "reports", description="Directory for CSV reports.",
        ),
        SettingSpec(
            "report.timestamp_format", "Timestamp format", "reporting",
            FieldType.STR, "%Y-%m-%dT%H:%M:%S%z",
            description="strftime format for report/log timestamps.",
        ),
        SettingSpec(
            "report.log_level", "Log level", "reporting", FieldType.ENUM,
            "INFO", choices=_LOG_LEVELS, description="Logging level.",
        ),
        SettingSpec(
            "report.retention_days", "Retention (days)", "reporting",
            FieldType.INT, 0, min=0, max=3650,
            description="Delete report CSVs older than N days (0 = keep all).",
        ),
        SettingSpec(
            "report.diagnostic_verbosity", "Diagnostic verbosity", "reporting",
            FieldType.ENUM, "normal", choices=_VERBOSITY,
            description="Diagnostic verbosity for reports/console.",
        ),
        SettingSpec(
            "include_password_in_report", "Include password in report",
            "reporting", FieldType.BOOL, False,
            description="WARNING: writes the candidate password to a CSV column "
                        "in your local, gitignored report.",
            help_text="Off by default so reports stay secret-free.",
        ),

        # --- Page 9: Advanced (Security) ----------------------------------
        SettingSpec(
            "security.http_status_codes", "Challenge HTTP codes", "security",
            FieldType.STRLIST, [403, 429],
            description="HTTP status codes that indicate a challenge.",
        ),
        SettingSpec(
            "security.blocking_text_patterns", "Blocking text patterns",
            "security", FieldType.STRLIST,
            ["too many attempts", "rate limit", "captcha", "account locked"],
            description="Text patterns indicating blocking/challenges.",
        ),
        SettingSpec(
            "security.captcha_selectors", "CAPTCHA selectors", "security",
            FieldType.STRLIST, [".g-recaptcha", ".h-captcha"],
            description="CSS selectors for CAPTCHA elements.",
        ),
        SettingSpec(
            "security.mfa_selectors", "MFA/2FA selectors", "security",
            FieldType.STRLIST, [".mfa-challenge", ".two-factor"],
            description="CSS selectors for MFA/2FA challenge elements.",
        ),
    ]


SPECS: List[SettingSpec] = _specs()
SPEC_BY_PATH: Dict[str, SettingSpec] = {s.path: s for s in SPECS}


def specs_for_page(page_id: str) -> List[SettingSpec]:
    return [s for s in SPECS if s.group == page_id]


def title_for_page(page_id: str) -> str:
    for p in PAGES:
        if p["id"] == page_id:
            return p["title"]
    return page_id


# ---------------------------------------------------------------------------
# Value get/set on a plain config dict.
# ---------------------------------------------------------------------------

def get_value(cfg: Dict[str, Any], path: str) -> Any:
    """Get a dotted value from a config dict ('' / None if missing)."""
    node: Any = cfg
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def set_value(cfg: Dict[str, Any], path: str, value: Any) -> None:
    """Set a dotted value, creating intermediate dicts as needed."""
    parts = path.split(".")
    node = cfg
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def default_config() -> Dict[str, Any]:
    """Build a default config dict from the spec defaults."""
    cfg: Dict[str, Any] = {}
    for spec in SPECS:
        if not spec.persist:
            continue
        default = spec.default
        if isinstance(default, list):
            default = list(default)
        set_value(cfg, spec.path, default)
    return cfg


def coerce_value(spec: SettingSpec, raw: Any) -> Any:
    """Coerce a (possibly string) input value into the field's type.

    Raises ValueError with a helpful message on invalid input.
    """
    if spec.type == FieldType.BOOL:
        if isinstance(raw, bool):
            return raw
        s = str(raw).strip().lower()
        if s in ("1", "true", "yes", "on", "y", "t"):
            return True
        if s in ("0", "false", "no", "off", "n", "f", ""):
            return False if s else False
        raise ValueError(f"{spec.label}: expected true/false, got {raw!r}")

    if spec.type == FieldType.INT:
        try:
            val = int(str(raw).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{spec.label}: expected an integer, got {raw!r}")
        _check_range(spec, val)
        return val

    if spec.type == FieldType.FLOAT:
        try:
            val = float(str(raw).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{spec.label}: expected a number, got {raw!r}")
        _check_range(spec, val)
        return val

    if spec.type == FieldType.STRLIST:
        if isinstance(raw, (list, tuple)):
            items = [str(x) for x in raw]
        else:
            items = [line.strip() for line in str(raw).splitlines()]
        items = [x for x in items if x != ""]
        return items

    if spec.type == FieldType.ENUM:
        val = str(raw).strip()
        if val not in spec.choices:
            raise ValueError(
                f"{spec.label}: must be one of {list(spec.choices)}, got {raw!r}"
            )
        return val

    # STR
    return "" if raw is None else str(raw)


def _check_range(spec: SettingSpec, value: float) -> None:
    if spec.min is not None and value < spec.min:
        raise ValueError(f"{spec.label}: must be >= {spec.min}")
    if spec.max is not None and value > spec.max:
        raise ValueError(f"{spec.label}: must be <= {spec.max}")


def validate_config(cfg: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate a config dict against the AppConfig pydantic model.

    Returns (ok, errors). Errors are human-readable strings.
    """
    # Drop non-persisted (secret) keys before validating/saving.
    clean = dict(cfg)
    for spec in SPECS:
        if not spec.persist and get_value(clean, spec.path) is not None:
            _unset_value(clean, spec.path)
    try:
        AppConfig(**clean)
        return True, []
    except ValidationError as e:
        errors = []
        for err in e.errors():
            loc = ".".join(str(p) for p in err.get("loc", []))
            msg = err.get("msg", "invalid value")
            errors.append(f"{loc or '(root)'}: {msg}")
        return False, errors
    except Exception as e:  # noqa: BLE001
        return False, [str(e)]


def _unset_value(cfg: Dict[str, Any], path: str) -> None:
    parts = path.split(".")
    node = cfg
    for part in parts[:-1]:
        node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            return
    if isinstance(node, dict):
        node.pop(parts[-1], None)


def save_config(path: str, cfg: Dict[str, Any], *, validate: bool = True,
                backup: bool = True) -> Tuple[bool, List[str], Optional[str]]:
    """Persist a config dict atomically with optional validation + backup.

    Returns (ok, errors, backup_path). When validation fails, nothing is
    written. Secrets are never persisted.
    """
    if validate:
        ok, errors = validate_config(cfg)
        if not ok:
            return False, errors, None

    backup_path = None
    if backup:
        try:
            bp = backup_config(path)
            backup_path = str(bp) if bp else None
        except OSError:
            backup_path = None

    write_config_atomic(path, cfg)
    return True, [], backup_path
