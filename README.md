# Authentication Audit Tool

A safe, configurable Python tool for authorized authentication testing against your own Next.js/React applications using Playwright. Designed with strict security controls for responsible testing.

## ⚠️ Important Security Notice

**This tool is for AUTHORIZED TESTING ONLY.** It is designed to test authentication on applications you own and control. 

- Never use against systems you don't own
- Never attempt to bypass security controls (CAPTCHA, MFA, rate limits, WAF)
- Never test credentials belonging to other users
- Always have written authorization before testing

## Features

- **Safe by Default**: Production mode allows only ONE password per run
- **Hostname Allowlist**: Validates target against explicit allowed hosts
- **HTTPS Enforcement**: Requires HTTPS except for localhost
- **Security Challenge Detection**: Stops immediately on CAPTCHA, rate limits, lockouts
- **No Credential Logging**: Passwords, tokens, cookies never logged or stored
- **Sanitized Reports**: CSV output with only diagnostic information
- **Configurable Selectors**: Works with Custom, Auth.js, Clerk, Supabase, NextAuth
- **Staging Mode**: Optional multi-password testing with strict limits (explicit opt-in required)

## Requirements

- **Python**: 3.10 or higher
- **OS**: Windows 11 (PowerShell), macOS, or Linux
- **Playwright Chromium**: Installed via Playwright CLI

## Quick Start (Windows 11 / PowerShell)

### 1. Clone and Navigate

```powershell
cd F:\main\My_Projects\auth-browser-lab
```

### 2. Create Virtual Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Playwright Chromium

```powershell
playwright install chromium
```

### 5. Create Configuration

```powershell
# Generate example configuration
python tester.py --create-example-config

# Edit config.json with your settings
notepad config.json
```

### 6. Create Password File

```powershell
# Generate example password file
python tester.py --create-example-password

# Rename and add your test password
rename password.txt.example password.txt
notepad password.txt
```

**Important**: For production mode, put EXACTLY ONE password in the file (one line, no extra blank lines).

### 7. Run Test

```powershell
# Run with default config.json
python tester.py

# Or specify config file
python tester.py --config config.json
```

### 8. View Results

- Watch the browser window for visual confirmation
- Check console output for result classification
- View CSV report in `reports/auth-test-YYYY-MM-DD.csv`

## Configuration Guide

### Required Settings

| Setting | Description | Example |
|---------|-------------|---------|
| `target_url` | Full login page URL | `https://app.example.com/login` |
| `allowed_hosts` | Array of allowed hostnames | `["app.example.com", "localhost"]` |
| `auth.username` | Your dedicated test account email | `security-test@example.com` |

### Authentication Provider Presets

The tool supports common auth providers through configuration. Set `auth.provider` and adjust selectors:

#### Custom Next.js/React Form
```json
{
  "auth": {
    "provider": "custom",
    "username_selector": "input[name=\"email\"]",
    "password_selector": "input[name=\"password\"]",
    "submit_selector": "button[type=\"submit\"]",
    "success_url_patterns": ["/dashboard", "/app"],
    "success_selectors": "[data-testid=\"user-menu\"], .user-profile",
    "failure_selectors": "[data-testid=\"error-message\"], .auth-error"
  }
}
```

#### Auth.js / NextAuth
```json
{
  "auth": {
    "provider": "authjs",
    "username_selector": "input#email",
    "password_selector": "input#password",
    "submit_selector": "button[type=\"submit\"]",
    "success_url_patterns": ["/dashboard"],
    "success_selectors": "[data-testid=\"user-menu\"]",
    "failure_selectors": "[data-testid=\"error-message\"]"
  }
}
```

#### Clerk
```json
{
  "auth": {
    "provider": "clerk",
    "username_selector": "input[name=\"identifier\"]",
    "password_selector": "input[name=\"password\"]",
    "submit_selector": "button[type=\"submit\"]",
    "success_url_patterns": ["/dashboard"],
    "success_selectors": ".clerk-user-button",
    "failure_selectors": ".clerk-form-error"
  }
}
```

#### Supabase Auth
```json
{
  "auth": {
    "provider": "supabase",
    "username_selector": "input[name=\"email\"]",
    "password_selector": "input[name=\"password\"]",
    "submit_selector": "button[type=\"submit\"]",
    "success_url_patterns": ["/dashboard", "/account"],
    "success_selectors": "[data-testid=\"user-avatar\"]",
    "failure_selectors": ".supabase-auth-error"
  }
}
```

### Full Configuration Reference

```json
{
  "target_url": "https://app.example.com/login",
  "allowed_hosts": ["app.example.com", "localhost"],
  "auth": {
    "provider": "custom",
    "username": "test@example.com",
    "username_selector": "input[name=\"email\"]",
    "password_selector": "input[name=\"password\"]",
    "submit_selector": "button[type=\"submit\"]",
    "success_url_patterns": ["/dashboard", "/home"],
    "success_selectors": "[data-testid=\"user-menu\"], .user-profile",
    "failure_selectors": "[data-testid=\"error-message\"], .auth-error"
  },
  "browser": {
    "browser": "chromium",
    "headless": false,
    "navigation_timeout_ms": 15000,
    "delay_before_submit_seconds": 3
  },
  "report": {
    "report_directory": "reports"
  },
  "security": {
    "http_status_codes": [403, 429],
    "blocking_text_patterns": [
      "too many attempts",
      "rate limit",
      "captcha",
      "temporarily blocked",
      "account locked",
      "access denied"
    ],
    "captcha_selectors": [
      "[data-testid*='captcha']",
      "iframe[src*='recaptcha']",
      ".g-recaptcha"
    ],
    "mfa_selectors": [
      "[data-testid*='mfa']",
      ".mfa-challenge"
    ]
  },
  "stop_on_security_challenge": true,
  "execution_mode": "production",
  "maximum_attempts": 1,
  "password_file": "password.txt"
}
```

## Execution Modes

### Production Mode (Default)
- **One password per run** - enforced by validation
- Stops immediately on any security challenge
- No automatic retries
- Safe for testing against production systems

```json
"execution_mode": "production",
"maximum_attempts": 1
```

### Staging Mode (Explicit Opt-In)
- Multiple passwords allowed (up to `maximum_attempts`, max 10)
- Requires manual confirmation before running
- Still stops on security challenges
- Use ONLY against staging/test environments with written authorization

```json
"execution_mode": "staging",
"maximum_attempts": 3
```

**To enable staging mode:**
1. Set `execution_mode: "staging"` in config
2. Set `maximum_attempts` (1-10)
3. Add multiple passwords to password.txt (one per line)
4. Run tool - you must type "yes" to confirm

## Understanding Results

### Result Categories

| Result | Meaning | Action |
|--------|---------|--------|
| `SUCCESS_CONFIRMED` | Explicit success indicator found (URL/selector) | Login works |
| `AUTHENTICATION_FAILED` | Explicit failure indicator found | Invalid credentials |
| `STOPPED_SECURITY_CHALLENGE` | CAPTCHA, MFA, or generic challenge | Review security settings |
| `STOPPED_RATE_LIMIT` | HTTP 429 or rate limit text | Check rate limiting config |
| `STOPPED_ACCESS_DENIED` | HTTP 403 or access denied | Check WAF/IP blocking |
| `INCONCLUSIVE` | No clear indicators | Manual browser review needed |
| `CONFIGURATION_ERROR` | Invalid config | Fix config.json |
| `NAVIGATION_ERROR` | Browser navigation failed | Check URL/selectors |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed (success or inconclusive) |
| 1 | Configuration/password file error |
| 2 | Test execution error |
| 3 | Security challenge stopped test |
| 130 | Interrupted by user (Ctrl+C) |

## CSV Report Format

Reports saved to `reports/auth-test-YYYY-MM-DD.csv`:

| Column | Description |
|--------|-------------|
| `timestamp_utc` | ISO 8601 timestamp |
| `target_host` | Hostname only (no credentials) |
| `authentication_provider` | Provider name |
| `execution_mode` | production/staging |
| `attempt_number` | 1-based attempt index |
| `result` | Classification result |
| `http_status` | Auth endpoint HTTP status |
| `security_challenge_detected` | true/false |
| `elapsed_time_ms` | Test duration |
| `diagnostic_summary` | Sanitized description |

**Never contains**: passwords, tokens, cookies, session data, full page content

## Finding Selectors

Use browser DevTools to find reliable selectors:

1. Open login page in browser
2. Right-click element → Inspect
3. Right-click in Elements panel → Copy → Copy selector
4. Prefer stable attributes: `data-testid`, `name`, `id`
5. Avoid brittle selectors: `nth-child`, generated class names

Example stable selectors:
```html
<!-- Good: data-testid -->
<input data-testid="email-input" name="email" />

<!-- Good: name attribute -->
<input name="email" type="email" />

<!-- Avoid: generated classes -->
<input class="css-1x2y3z4" />
```

## Troubleshooting

### Browser doesn't open / Playwright errors
```powershell
# Reinstall browsers
playwright install --force chromium

# Check dependencies
playwright install-deps
```

### "Target hostname not in allowed_hosts"
- Add your target hostname to `allowed_hosts` in config.json
- Must match exactly (subdomains count as different hosts)

### "HTTPS required for non-localhost hosts"
- Use HTTPS for production URLs
- For local development, use `http://localhost:3000` and add `localhost` to allowed_hosts

### "Exactly one password required" (Production mode)
- Edit password.txt to contain only ONE non-empty line
- Remove extra blank lines

### "Too many passwords" (Staging mode)
- Reduce passwords in file to ≤ maximum_attempts
- Or increase maximum_attempts in config (max 10)

### Selector not found / Timeout
- Increase `navigation_timeout_ms`
- Verify selector in DevTools Console: `document.querySelector('your-selector')`
- Check if element is in iframe (need frame locator)

### Test shows INCONCLUSIVE
- Add success/failure selectors to config
- Check `success_url_patterns` matches post-login URL
- Review browser visually during test run

## Running Unit Tests

```powershell
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_config.py -v
pytest tests/test_password_file.py -v
pytest tests/test_result_classification.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing
```

## Project Structure

```
auth-audit/
├── tester.py                 # Main entry point
├── config.example.json       # Example configuration
├── password.txt.example      # Example password file
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── .gitignore                # Git ignore rules
├── reports/
│   └── .gitkeep             # Keeps directory in git
├── src/
│   ├── __init__.py
│   ├── config.py            # Configuration management
│   ├── password_handler.py  # Secure password file handling
│   ├── security_detector.py # Challenge detection
│   ├── result_classifier.py # Result classification
│   ├── reporter.py          # CSV reporting
│   └── browser_automation.py # Playwright orchestration
└── tests/
    ├── test_config.py
    ├── test_password_file.py
    └── test_result_classification.py
```

## Security Limitations

This tool intentionally does NOT:

- ❌ Brute-force passwords
- ❌ Rotate IPs/proxies
- ❌ Bypass CAPTCHA/MFA
- ❌ Evade WAF/rate limits
- ❌ Access other users' accounts
- ❌ Store credentials
- ❌ Auto-retry on failure
- ❌ Resume interrupted sequences

## Responsible Use Guidelines

1. **Only test systems you own** or have explicit written authorization for
2. **Use dedicated test accounts** - never production user accounts
3. **Run during low-traffic periods** to avoid impacting users
4. **Coordinate with your security team** before testing
5. **Document your testing scope** and get approval
6. **Review results manually** - don't rely solely on automated classification
7. **Report findings responsibly** through your organization's security process

## License

Internal use only - Authorized Security Testing Tool

## Support

For issues or questions:
1. Check troubleshooting section above
2. Run with `--verbose` for detailed output
3. Review unit tests for expected behavior
4. Consult Playwright documentation for browser automation issues