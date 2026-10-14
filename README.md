# Authentication Audit Tool

A safe, config-driven Python + Playwright tool for **authorized authentication
testing against websites you own or are explicitly authorized to test**. It
processes **every non-empty password entry** in `password.txt` sequentially, in
file order, using a **dedicated test account you control**, and never attempts
to bypass CAPTCHA, MFA, WAF, rate limits, or account lockouts.

> ⚠️ **Authorized use only.** Only target hosts you own or have written
> authorization to test (declared in `allowed_hosts`). Use a dedicated test
> account — never another user's account or production credentials.

---

## Features

| Feature | Description |
|---------|-------------|
| **Config-driven selectors** | Works with any username/password form |
| **Explicit allowlist** | You declare authorized hosts via `allowed_hosts` |
| **HTTPS enforced** | Required for all non-local hosts (HTTP only for loopback) |
| **Process whole file** | Every non-empty entry processed once, in file order |
| **Challenge stop** | Stops immediately on CAPTCHA/MFA/lockout/rate-limit/403/429 |
| **No bypasses** | Never solves/bypasses challenges; no proxy/evasion tricks |
| **No credential logging** | Passwords/tokens/cookies never logged or stored |
| **Sanitized CSV** | Consolidated report with only safe diagnostics |

There is **no** per-run attempt-limit or execution-mode setting — those were
intentionally removed. The whole password file is processed in order.

---

## Requirements

- **Python**: 3.10+
- **OS**: Windows 11 (PowerShell), macOS, or Linux
- **Playwright Chromium**: installed via the Playwright CLI

---

## Quick Start (Windows 11 / PowerShell)

```powershell
git clone https://github.com/Jomohamad/auth-browser-lab.git
cd F:\main\My_Projects\auth-browser-lab
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
playwright install chromium
```

### Configure your authorized target

Edit `config.json` (gitignored) — or generate an example:

```powershell
python tester.py --create-example-config
```

Key fields:

| Field | Meaning |
|-------|---------|
| `target_url` | Login page URL (must be HTTPS unless localhost) |
| `allowed_hosts` | Hosts you are authorized to test |
| `auth.username` | Your **dedicated test account** |
| `auth.username_selector` | CSS selector for the username field |
| `auth.password_selector` | CSS selector for the password field |
| `auth.submit_selector` | CSS selector for the submit/login button |
| `auth.success_url_patterns` | Post-login URL paths that confirm success |
| `auth.success_selectors` | Authenticated-page selectors (optional) |
| `auth.failure_selectors` | Error-message selectors |
| `auth.success_on_navigation_without_failure` | Operator-defined success signal (see below) |
| `password_file` | Candidate password list (gitignored) |

**When the login error element is your only correctness signal:** set
`auth.success_on_navigation_without_failure: true`. With this on, a submit that
**navigates the browser off the login page** and shows **no** configured failure
element is classified as `SUCCESS_CONFIRMED`. This is how the Delta LMS config
works — `#errorLbl` marks a wrong password; its absence after a real navigation
means success. It still never claims success if the failure element is present
or the browser stays on the login page.

### Provide your dedicated test credentials

```powershell
python tester.py --create-example-password
rename password.txt.example password.txt
notepad password.txt      # one candidate password per line
```

`password.txt` is gitignored and never logged. Username can also come from the
`AUTH_TEST_USERNAME` environment variable.

### Run

```powershell
python tester.py --config config.json
```

Chromium opens (headed by default) and processes each entry against your login
page. Results are summarized in the console and written to
`reports/auth-test-YYYY-MM-DD.csv`.

**Loop stops immediately on confirmed success.** The loop stops as soon as an
entry yields `SUCCESS_CONFIRMED` (a configured success indicator is observed),
so remaining entries are never processed. It also stops on a detected security
challenge. `AUTHENTICATION_FAILED` and `INCONCLUSIVE` do **not** stop the run —
and `INCONCLUSIVE` is never treated as success. When it stops on success you
get a block like:

```text
Authentication result: SUCCESS_CONFIRMED
Matched test fixture: entry #N
Matched password (terminal only): <the working candidate>
Further test entries: NOT PROCESSED (M remaining: entries N+1..N+M)
Stop reason: AUTHENTICATION_SUCCESS
```

The matched password is printed **to the terminal only** (for your own
authorized testing) and is **never** written to the CSV report or any log — the
report redacts all candidate passwords.

---

## Already-configured example: `dulms.deltauniv.edu.eg`

`config.json` ships pre-configured for the login page at
`https://dulms.deltauniv.edu.eg/login.aspx` using selectors verified in the
browser:

```json
"auth": {
  "username_selector": "#txtname",
  "password_selector": "#txtPass",
  "submit_selector": "#Button1",
  "failure_selectors": ["#errorLbl"]
}
```

- `#txtname` — username field
- `#txtPass` — password field
- `#Button1` — login/submit button
- `#errorLbl` — error label (shows "Please enter correct username" / invalid
  credentials). Its presence ⇒ `AUTHENTICATION_FAILED`; absence ⇒ success is
  only confirmed if a success indicator is also observed.

### What you must still provide

Only you can supply the real credentials and success signal (they are never
committed and never guessed by the tool):

1. **Username** — `auth.username` is already set to your test account in
   `config.json` (you can also export `AUTH_TEST_USERNAME` instead).
2. **Real password** — put your actual test password in `password.txt`
   (one line). The file ships with the placeholder
   `CHANGE_ME_TO_YOUR_TEST_PASSWORD`; if it is still that placeholder you will
   get `AUTHENTICATION_FAILED` (wrong password) even with a correct username.
3. **Success indicator** — `success_selectors` is empty and
   `success_url_patterns` defaults to `["/default.aspx"]`. Log in manually once,
   note the URL you land on (and/or an element that only exists when logged in,
   e.g. a logout link), and set one of them, for example:
   ```json
   "success_url_patterns": ["/default.aspx"],
   "success_selectors": ["a[href*=\"logout\"]"]
   ```
   `/default.aspx` is a default guess — verify it in the browser. Without a
   matching indicator, a correct login reports `INCONCLUSIVE` (the tool never
   infers success).

---

## Troubleshooting / interpreting your result

| What you see | Why | What to do |
|--------------|-----|------------|
| `AUTHENTICATION_FAILED` + `#errorLbl` ("Please enter correct username and password") | The site **rejected the credentials** — the tool read this from your page's own error label. | The script is working. Put the **correct password** in `password.txt` (and check the username). |
| `INCONCLUSIVE` | The form submitted but **no configured success/failure indicator matched**. | Add the real post-login path to `success_url_patterns`, or an authenticated-only element to `success_selectors`. |
| `SUCCESS_CONFIRMED` | A configured **success indicator was observed**. | Nothing — login works. |
| `SELECTOR_NOT_FOUND` | A configured selector was missing/invisible/ambiguous/in an iframe. | Re-copy the selector in DevTools; the console prints the exact diagnostic (e.g., "matched 0 elements"). |
| `LOGIN_PAGE_NOT_FOUND` | The login page returned HTTP 404. | Check `target_url`. |
| `UNAUTHORIZED_HOST_BLOCKED` | A redirect went to a host not in `allowed_hosts`; credentials were **not** submitted there. | Add that host to `allowed_hosts` only if you're authorized to test it. |
| `STOPPED_SECURITY_CHALLENGE` / `STOPPED_RATE_LIMIT` / `STOPPED_ACCESS_DENIED` | A CAPTCHA/MFA/lockout/rate-limit/403/429 signal was detected. | The run stops by design. Do not retry-loop; respect the control. |

Note: a real `AUTHENTICATION_FAILED` for this site is normal until
`password.txt` holds the correct password — it is not a code fault.

---

## Finding selectors for any other site

1. Open the login page, press **F12** → **Elements**.
2. Right-click the field → Inspect → right-click the node → **Copy** →
   **Copy selector**.
3. Prefer stable attributes: `id`, `name`, `data-testid`.
4. For the error message and any authenticated-only element, copy those
   selectors into `failure_selectors` / `success_selectors`.

---

## Result categories

| Result | Meaning |
|--------|---------|
| `SUCCESS_CONFIRMED` | A configured success indicator was observed |
| `AUTHENTICATION_FAILED` | A configured failure indicator was observed |
| `LOGIN_PAGE_NOT_FOUND` | The login page returned HTTP 404 |
| `SELECTOR_NOT_FOUND` | A configured selector was missing/invisible/ambiguous/in an iframe |
| `FORM_NOT_READY` | The login form could not be found or readied |
| `STOPPED_SECURITY_CHALLENGE` | CAPTCHA / MFA / lockout / generic challenge |
| `STOPPED_RATE_LIMIT` | HTTP 429 or rate-limit text |
| `STOPPED_ACCESS_DENIED` | HTTP 403 or access-denied text |
| `NAVIGATION_ERROR` | Navigation failed |
| `UNAUTHORIZED_HOST_BLOCKED` | Redirected to a host not in `allowed_hosts` |
| `INCONCLUSIVE` | No configured indicator matched — manual review needed |
| `CONFIGURATION_ERROR` | Invalid configuration |

---

## CSV report

One consolidated report per day: `reports/auth-test-YYYY-MM-DD.csv`, one row
per processed entry.

| Column | Description |
|--------|-------------|
| `timestamp_utc` | ISO 8601 timestamp |
| `attempt_number` / `total_entries` | Index within run / total non-empty entries |
| `result` | Result category |
| `http_status` | Observed auth-related HTTP status |
| `security_challenge_detected` | true/false |
| `elapsed_time_ms` | Time for this entry |
| `diagnostic_summary` | Sanitized diagnostic text |
| `target_host`, `authentication_provider` | Context |
| `login_page_status` / `auth_response_status` | Split document/API status |
| `final_page_path` | Final URL path (no query/fragment) |
| `page_title`, `form_detected`, `selector_diagnostic` | Diagnostics |

It never contains passwords, hashes, cookies, tokens, authorization headers,
request bodies, full page HTML, or full URLs with query strings/fragments.

---

## Tests

```powershell
python -m pytest tests -v
```

The suite covers configuration/allowlist/HTTPS validation, full-file password
processing (order, blank lines, CRLF/LF, no over-normalization, error cases),
result classification, security-challenge detection, redirect/origin blocking,
CSV sanitization, and confirms no attempt-limit config remains. Unit tests use
mocks and fixtures only — they never contact a live website. Live runs against
your own site are performed by `tester.py`, not the test suite.

---

## Project structure

```
auth-browser-lab/
├── tester.py                  # CLI entry point
├── config.json                # Authorized target config (gitignored)
├── config.example.json        # Example configuration
├── password.txt               # Candidate password list (gitignored)
├── password.txt.example       # Example password file
├── requirements.txt
├── pyproject.toml
├── README.md
├── .gitignore
├── reports/ (auth-test-YYYY-MM-DD.csv)
├── src/auth_audit/
│   ├── config.py              # Config + allowlist + HTTPS enforcement
│   ├── password_handler.py    # Full-file reading (no attempt limit)
│   ├── security_detector.py   # Challenge detection
│   ├── result_classifier.py   # Result classification
│   ├── reporter.py            # Sanitized CSV reporting
│   └── browser_automation.py  # Playwright orchestration
└── tests/
    ├── test_config.py
    ├── test_password_file.py
    ├── test_result_classification.py
    ├── test_url_allowlist.py
    └── test_attempt_limit_removed.py
```

---

## Responsible use

- Test only hosts you own / are authorized to test (declare them in
  `allowed_hosts`).
- Use a dedicated test account; never another user's account.
- The tool **stops** on challenges and **never** bypasses CAPTCHA/MFA/WAF/rate
  limits/lockouts — respect those controls.
- Keep credentials out of source control (`config.json`, `password.txt`,
  `.env` are gitignored).
