# Signed by JOE
"""Low-level Playwright browser helpers.

These helpers are kept separate from the authentication *flow* so they can be
unit-tested and reused without a full run. They provide:

  * launch_browser(): launch the configured browser with explicit arguments,
  * wait_for_selector_with_diagnostics(): human-readable selector diagnostics
    (not found / ambiguous / not visible / inside iframe / timeout),
  * extract_selector_from_error(): pull a CSS selector out of a Playwright
    timeout exception for diagnostics.
"""

import re
from typing import Optional

from playwright.sync_api import BrowserType as PW_BrowserType, Page


def launch_browser(
    playwright, browser: str = "chromium", headless: bool = False
):
    """Launch the requested browser engine.

    Chromium runs with automation-control features disabled when headed, to
    reduce obvious automation fingerprinting during authorized functional
    checks (this is not a bypass of any challenge).

    Args:
        playwright: The Playwright sync root object.
        browser: One of "chromium", "firefox", "webkit".
        headless: Whether to run headless.

    Returns:
        A launched Playwright Browser.
    """
    getter = getattr(playwright, browser, None)
    if getter is None:
        raise ValueError(f"Unsupported browser engine: {browser!r}")

    args = []
    if browser == "chromium" and not headless:
        args.append("--disable-blink-features=AutomationControlled")

    return getter.launch(headless=headless, args=args)


def build_context_options(viewport_width: int = 1280, viewport_height: int = 720) -> dict:
    """Return Playwright context options (viewport)."""
    return {
        "viewport": {
            "width": int(viewport_width),
            "height": int(viewport_height),
        }
    }


def wait_for_selector_with_diagnostics(
    page: Page,
    selector: str,
    field_name: str,
    timeout: int,
) -> Optional[str]:
    """Wait for a selector, returning a diagnostic string on any issue.

    Returns None when the selector is present and visible (the element was also
    awaited to a visible state). Otherwise returns a human-readable message
    describing why the selector was unusable (0 matches, ambiguous, hidden,
    present only inside an iframe, or a timeout).
    """
    try:
        count = page.locator(selector).count()
        if count == 0:
            # The field may live inside an iframe; surface that specifically.
            frames = getattr(page, "frames", [])
            for frame in frames:
                try:
                    if frame.locator(selector).count() > 0:
                        frame_label = getattr(frame, "name", None) or getattr(
                            frame, "url", "?"
                        )
                        return (
                            f"Selector '{selector}' for {field_name} found in "
                            f"iframe (frame: {frame_label}) but not in main frame"
                        )
                except Exception:
                    pass
            return f"Selector '{selector}' for {field_name} matched 0 elements"
        elif count > 1:
            return (
                f"Selector '{selector}' for {field_name} matched {count} "
                "elements (ambiguous)"
            )

        element = page.locator(selector).first
        if not element.is_visible():
            return (
                f"Selector '{selector}' for {field_name} matched 1 element "
                "but it is not visible"
            )

        element.wait_for(state="visible", timeout=timeout)
        return None

    except Exception as e:  # noqa: BLE001 - diagnostics must never raise
        error_str = str(e)
        if "Timeout" in error_str:
            try:
                count = page.locator(selector).count()
                if count > 0:
                    return (
                        f"Selector '{selector}' for {field_name} matched "
                        f"{count} element(s) but not visible within {timeout}ms"
                    )
                return (
                    f"Selector '{selector}' for {field_name} matched 0 elements "
                    f"(timeout after {timeout}ms)"
                )
            except Exception:
                pass
        return (
            f"Selector '{selector}' for {field_name} error: {error_str[:100]}"
        )


def extract_selector_from_error(error: str) -> str:
    """Extract a CSS selector from a Playwright timeout error message."""
    match = re.search(r'locator\("([^"]+)"\)', error)
    if match:
        return f"Timeout waiting for '{match.group(1)}'"
    match = re.search(r"locator\('([^']+)'\)", error)
    if match:
        return f"Timeout waiting for '{match.group(1)}'"
    return f"Selector timeout: {error[:150]}"
