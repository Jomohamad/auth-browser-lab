# Authentication Audit Tool

A safe, **config-driven** Python + Playwright tool for **authorized
authentication testing against software you own or are explicitly authorized to
test**. It has an interactive settings TUI, a full CLI, environment/dependency
diagnostics, sanitized CSV reporting, and strict safety guardrails.

> ⚠️ **Authorized use only.** Test only hosts you own or are authorized to test.
> Use a **dedicated test account** — never someone else's account or real
> production credentials. The tool never bypasses CAPTCHA/MFA/WAF/rate-limits/
> lockouts; it **stops** on them.

---

## Safety policy (read first)

This tool is intentionally restrictive about *where* credential testing may run:

| Target | What is allowed |
|--------|-----------------|
| **Any host you declare** in `allowed_hosts` | Full password-list processing (every candidate once, in order). |
| **Everything else** | Refused **before** any browser interaction. |

- A host must be explicitly listed in `allowed_hosts`; the target host must match.
- **HTTPS** is required for every non-local host (HTTP only for loopback targets such as `127.0.0.1` / `localhost`).
- Public domains such as your own site are fully supported — just add the host to `allowed_hosts` and use HTTPS.
- **Success** requires an explicit indicator (authenticated URL path or an authenticated-only element). A bare HTTP 302/redirect is **never** success.
- Uncertain results stay `INCONCLUSIVE` (never treated as success).
- Never bypass CAPTCHA/MFA/WAF/rate-limits/lockouts; the tool **stops** on them.

---

## Requirements

- **Python**: 3.10+
- **OS**: Windows 11 (PowerShell), macOS, or Linux
- **Playwright Chromium**: installed via the Playwright CLI
- Optional: **Textual** + **Rich** for the interactive settings TUI

---

## Windows 11 setup (PowerShell)

```powershell
git clone https://github.com/Jomohamad/auth-browser-lab.git
cd F:\main\My_Projects\auth-browser-lab

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

# Interactive settings TUI (optional but recommended)
python -m pip install -e ".[tui]"

# Install the Chromium engine used by Playwright
python -m playwright install chromium
```

`playwright` must be installed **and** the Chromium browser downloaded (the two
are separate). `python tester.py --doctor` verifies both.

---

## CLI reference (`python tester.py --help`)

Run the full help page with:

```powershell
python tester.py --help
```

| Command | Purpose |
|---------|---------|
| `--help` | Show all available commands and options. |
| `--version` | Print the application version. |
| `--settings` | Launch the interactive settings TUI (**never** starts a browser or an auth test). |
| `--doctor` | Environment/configuration diagnostics (no changes). |
| `--config PATH` | Choose the config file (default `config.json`). |
| `--check-updates` | Report installed vs latest-compatible versions (**read-only**; installs nothing). |
| `--update-deps` | Interactively update declared dependencies after confirmation. |
| `--yes` | With `--update-deps`, confirm non-interactively. |
| `--exclude-breaking` | With `--update-deps`, skip MAJOR version bumps. |
| `--headless` | Force a headless browser for this run. |
| `--username TEXT` | Override the test username (also via `AUTH_TEST_USERNAME`). |
| `--password-file PATH` | Override the password file path from config. |
| `--password TEXT` | Provide a single synthetic test password at run time (functional check). |
| `--prompt-password` | Prompt for the single synthetic test password. |
| `--always-on-top` / `--no-always-on-top` | Toggle Windows console always-on-top for this run. |
| `--create-example-config` | Write `config.example.json` and exit. |
| `--create-example-password` | Write `password.txt.example` and exit. |
| `--verbose` | Verbose error output (tracebacks). |

### PowerShell examples

```powershell
# Diagnose the environment and configuration
python tester.py --doctor

# Interactive settings editor (no browser)
python tester.py --settings

# Run against your authorized target (headless)
python tester.py --config config.json --headless

# Check for outdated dependencies (read-only)
python tester.py --check-updates

# Update dependencies with an explicit confirmation prompt
python tester.py --update-deps

# Non-interactive update that skips MAJOR bumps
python tester.py --update-deps --yes --exclude-breaking
```

### Configuration precedence (highest first)

1. **CLI options** (e.g. `--headless`, `--username`)
2. **Environment variables** (`AUTH_TEST_USERNAME`, `AUTH_TEST_PASSWORD`)
3. **Config file** values (`config.json`)

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | OK (including success, or a refused/inapplicable dependency action). |
| `1` | Configuration/usage error (bad config, denied host, invalid CLI combination). |
| `2` | Run error (`NAVIGATION_ERROR` / `CONFIGURATION_ERROR`). |
| `3` | Security stop (CAPTCHA/MFA/rate-limit/403/429 detected). |
| `130` | Interrupted with Ctrl-C. |

---

## Interactive settings TUI (`--settings`)

Launch with `python tester.py --settings`. It never starts a browser and never
runs an authentication test.

**Navigation & keys** (consistent on every page)

- **Up / Down**: move the `>` selection between menu items and fields.
- **Enter**: select / activate the highlighted item.
- **Left / Right**: cycle choices on dropdown (enum) fields where applicable.
- **Mouse**: click a menu item or field to select it; click the same item again
  (or press Enter) to activate it. Buttons perform their action on click.
- **Escape / Backspace**: return to the previous screen.
- Unsaved changes are validated and saved atomically (with a timestamped
  backup); exiting with unsaved changes prompts for confirmation.
- Long pages scroll with the mouse wheel where the terminal supports it;
  keyboard navigation always works even without mouse support.

**Pages** (each uses the same plain-text header, `=` / `-` separators, `>`
selected-item marker, shortcut hints, and a bottom action bar with
`[Save]`, `[Reset page]`, `[Reset all]`, `[Back]`)

1. **Overview** — version, active config file, Python version, dependency
   health, Chromium status, and whether config validation passed.
2. **Target Configuration** — `target_url`, `allowed_hosts`.
3. **Authentication Configuration** — provider, form selectors, success /
   failure indicators. Adapters/notes are provided for Auth.js/NextAuth,
   Clerk, and Supabase (each has a different form/navigation shape).
4. **Browser** — engine, headless, viewport, navigation timeout, delays, and the
   Windows console **always-on-top** toggle.
5. **Execution** — `stop_on_security_challenge`, `password_file`.
6. **Reporting** — report directory, timestamp format, log level, retention,
   diagnostic verbosity, and the (off‑by‑default) `include_password_in_report`.
7. **Dependencies & Tools** — installed versions, check for compatible updates,
   and a clearly confirmed update action.
8. **Advanced (Security)** — challenge HTTP codes, blocking text patterns,
   CAPTCHA/MFA selectors.

(The dedicated **Test Account** page was removed; the masked password is not
exposed as a standalone TUI page. At run time the password is still resolved
from `--password`, `AUTH_TEST_PASSWORD`, Windows Credential Manager, or an
interactive masked prompt — never written to `config.json`.)

**Saving** validates every value, rejects invalid hosts/URLs/selectors and
incompatible combinations, **preserves unrelated settings**, writes
**atomically** (write-to-temp then `os.replace`), and creates a **timestamped
backup** first. You can reset a page or the whole config to safe defaults.

---

## Secret storage

- **Passwords/tokens are never written into the JSON configuration.**
- At run time the test password is resolved in this order:
  1. explicit `--password`,
  2. environment variable `AUTH_TEST_PASSWORD`,
  3. **Windows Credential Manager** (generic credential
     `auth-browser-lab/test-credential`),
  4. an interactive, **masked** prompt (`--prompt-password`).
- In the TUI, the password field is masked and stored only in the credential
  store — you can replace or clear it without ever showing its current value.
- Username may live in config (it is a non-secret identifier) and can also come
  from `AUTH_TEST_USERNAME`.
- CSV reports contain **no** passwords, hashes, cookies, tokens, auth headers,
  request bodies, full HTML, or full URLs with query/fragment. The optional
  `include_password_in_report` column is **off by default**.

---

## Browser installation & troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `ModuleNotFoundError: auth_audit` | Activate the venv and `python -m pip install -e .`. |
| Browser won't launch | `python -m playwright install chromium`. |
| "Remote version check skipped (offline)" | No network; that is **not** confirmation packages are current. |
| `--settings` says Textual missing | `python -m pip install -e ".[tui]"`. |
| `UNAUTHORIZED_HOST_BLOCKED` | A redirect left `allowed_hosts`; credentials were **not** submitted there. |
| `SELECTOR_NOT_FOUND` | Re-copy the selector; the console prints the exact diagnostic (0 matches / ambiguous / hidden / in iframe). |

Run `python tester.py --doctor` to see Python, package, Playwright, and Chromium
status in one place.

---

## Always-on-top (Windows)

- Opt-in via `browser`/`always_on_top` in config, `--always-on-top`, or the
  settings TUI.
- Implemented with the Win32 API (`GetConsoleWindow` + `SetWindowPosW`
  `HWND_TOPMOST`). It uses `SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE`, so it
  **never steals keyboard focus** and **never moves/resizes** the window without
  your approval.
- It is a **best-effort** feature: in IDE/embedded terminals without a real
  console HWND (or on macOS/Linux), it is skipped and a clear **warning** is
  shown. The tool never claims the terminal is on top if the operation failed.

---

## Running the test suite

```powershell
python -m pytest tests -q
```

The suite covers CLI behavior, the settings schema and atomic/secret-free config
persistence, dependency diagnostics (network/browser/pip are mocked), the
Windows always-on-top helper (OS mocked), the safety target policy, CSV
sanitization, and the result classifier. Unit tests never contact a live
website.

---

## Result states & CSV reports

| Result | Meaning |
|--------|---------|
| `SUCCESS_CONFIRMED` | A configured success indicator was observed. |
| `AUTHENTICATION_FAILED` | A configured failure indicator was observed. |
| `LOGIN_PAGE_NOT_FOUND` | The login page returned HTTP 404. |
| `SELECTOR_NOT_FOUND` | A configured selector was missing/hidden/ambiguous/in an iframe. |
| `FORM_NOT_READY` | The login form could not be found or readied. |
| `STOPPED_SECURITY_CHALLENGE` | CAPTCHA / MFA / lockout / generic challenge. |
| `STOPPED_RATE_LIMIT` | HTTP 429 or rate-limit text. |
| `STOPPED_ACCESS_DENIED` | HTTP 403 or access-denied text. |
| `NAVIGATION_ERROR` | Navigation failed. |
| `UNAUTHORIZED_HOST_BLOCKED` | Redirected off `allowed_hosts`; credentials not submitted. |
| `INCONCLUSIVE` | No configured indicator matched — manual review needed. |
| `CONFIGURATION_ERROR` | Invalid configuration. |

On success the terminal prints a stop block such as:

```text
Authentication result: SUCCESS_CONFIRMED
Matched test fixture: entry #1
Matched password (terminal only): <the working candidate>
Further test entries: NONE (this was the final entry)
Stop reason: AUTHENTICATION_SUCCESS
```

The matched password is printed to the **terminal only** and never written to
the CSV report or logs.

### CSV report

One consolidated report per day: `reports/auth-test-YYYY-MM-DD.csv`, one row per
processed entry. Columns include `timestamp_utc`, `attempt_number`,
`total_entries`, `result`, `http_status`, `security_challenge_detected`,
`elapsed_time_ms`, `diagnostic_summary`, `target_host`,
`authentication_provider`, `login_page_status`, `auth_response_status`,
`final_page_path`, `page_title`, `form_detected`, `selector_diagnostic`, and
(only when you opt in) `candidate_password`. It never contains secrets.

---

## Configuration reference

Every field below is editable in the settings TUI (see also
`config.example.json`):

```jsonc
{
  "target_url": "http://127.0.0.1:8765/login",   // required; HTTPS for non-local
  "allowed_hosts": ["127.0.0.1", "localhost"],   // you are authorized for these
  "auth": {
    "provider": "custom",                        // custom|authjs|nextauth|clerk|supabase
    "username": "fixture_user",                  // non-secret identifier
    "username_selector": "#username",
    "password_selector": "#password",
    "submit_selector": "#login-btn",
    "success_url_patterns": ["/app/dashboard"],  // authenticated URL paths
    "success_selectors": ["a[href*='logout']"],  // authenticated-only elements
    "failure_selectors": ["#login-error"],       // login error elements
    "success_on_navigation_without_failure": false
  },
  "browser": {
    "browser": "chromium",                       // chromium|firefox|webkit
    "headless": false,
    "navigation_timeout_ms": 15000,
    "delay_before_submit_seconds": 1,
    "inter_entry_delay_seconds": 0,              // pacing between candidates
    "viewport_width": 1280,
    "viewport_height": 720
  },
  "report": {
    "report_directory": "reports",
    "timestamp_format": "%Y-%m-%dT%H:%M:%S%z",
    "log_level": "INFO",                         // DEBUG|INFO|WARNING|ERROR
    "retention_days": 0,                         // 0 = keep all
    "diagnostic_verbosity": "normal"             // minimal|normal|verbose
  },
  "security": {
    "http_status_codes": [403, 429],
    "blocking_text_patterns": ["rate limit", "captcha", "account locked"],
    "captcha_selectors": [".g-recaptcha", ".h-captcha"],
    "mfa_selectors": [".mfa-challenge", ".two-factor"]
  },
  "stop_on_security_challenge": true,           // always stop on challenges
  "always_on_top": false,                        // Windows console (best-effort)
  "password_file": "password.txt",               // candidate list
  "include_password_in_report": false            // off => reports stay secret-free
}
```

---

## Project structure

```
auth-browser-lab/
├── tester.py                  # CLI entry point (thin shim -> auth_audit.cli)
├── config.json                # Your config (gitignored)
├── config.example.json        # Example configuration
├── password.txt               # Candidate list (gitignored)
├── password.txt.example
├── requirements.txt
├── pyproject.toml
├── README.md
├── .gitignore
├── reports/                   # auth-test-YYYY-MM-DD.csv
├── src/auth_audit/
│   ├── __init__.py
│   ├── config.py              # Config model, allowlist/HTTPS, atomic save
│   ├── schema.py              # Declarative schema of every field
│   ├── credentials.py         # Secret resolution (env / CredMgr / prompt)
│   ├── password_handler.py    # Full-file reading (no attempt cap)
│   ├── security.py            # Challenge detection
│   ├── result_classifier.py   # Result classification
│   ├── reporting.py           # Sanitized CSV reporting
│   ├── browser.py             # Playwright launch + selector diagnostics
│   ├── auth_flow.py           # Orchestration + run policy
│   ├── dependency_manager.py  # Dependency/tool diagnostics + controlled updates
│   ├── windows_console.py     # Windows always-on-top (best-effort)
│   ├── cli.py                 # argparse CLI + exit codes
│   ├── settings_tui.py        # Textual settings TUI
│   └── tui/                   # Textual screen components (base, pages, entries, confirm, field_edit)
└── tests/
    ├── test_cli.py
    ├── test_config.py
    ├── test_schema.py
    ├── test_settings_config.py
    ├── test_settings_tui.py
    ├── test_dependencies.py
    ├── test_windows_console.py
    ├── test_result_classification.py
    ├── test_url_allowlist.py
    ├── test_success_stop.py
    ├── test_password_file.py
    ├── test_attempt_limit_removed.py
    └── test_credentials.py
```

---

## Responsible use

- Test only hosts you own / are authorized to test (declare them in
  `allowed_hosts`).
- Use a **dedicated** test account; never another user's account.
- The tool **stops** on challenges and **never** bypasses CAPTCHA/MFA/WAF/rate
  limits/lockouts — respect those controls.
- Keep credentials out of source control (`config.json`, `password.txt`,
  `.env` are gitignored). Secrets live in env vars or Windows Credential
  Manager, never in `config.json`.

Signed by JOE.
