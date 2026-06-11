"""
browser_crawler.py — Playwright-based crawler for JS-protected pages.

Handles Cloudflare-like challenges, vshield, and other anti-bot systems by:
  - Running a real Chromium instance in headful mode
  - Injecting stealth JS to mask automation signals
  - Simulating human mouse movement, scrolling, and random delays
  - Persisting cookies per domain to skip repeat challenges
  - Retrying up to MAX_RETRIES times with challenge detection

Public API
----------
    fetch_with_browser(url: str) -> str
        Returns the final HTML after bypassing anti-bot protection.
        Raises BrowserCrawlerError only after all retries are exhausted.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import time
from pathlib import Path
from urllib.parse import urlparse

from .proxy import get_outbound_proxy

# Run headless when there is no display server (e.g. Docker without Xvfb).
# Set PLAYWRIGHT_HEADFUL=1 explicitly to force headed mode locally.
_HEADLESS: bool = not bool(
    os.environ.get("PLAYWRIGHT_HEADFUL") or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

MAX_RETRIES = 3
PAGE_LOAD_TIMEOUT_MS = 30_000  # 30 s
TOTAL_TIMEOUT_S = 45  # hard cap per fetch_with_browser() call

# Delays simulating human behaviour (seconds)
HUMAN_DELAY_MIN = 3.0
HUMAN_DELAY_MAX = 8.0
CHALLENGE_EXTRA_WAIT_MIN = 5.0
CHALLENGE_EXTRA_WAIT_MAX = 10.0

# Directory that stores per-domain cookie files
COOKIE_STORE_DIR = Path(os.environ.get("CTI_COOKIE_STORE", "/tmp/cti_cookies"))  # noqa: S108

# Viewport choices (width, height) — picked randomly each session
_VIEWPORTS = [
    (1280, 800),
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1920, 1080),
]

# Rotating realistic user-agents
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.7049.115 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
]

# Strings that indicate an anti-bot challenge is still active
_CHALLENGE_MARKERS = [
    "checking your browser",
    "please wait",
    "just a moment",
    "ddos protection",
    "ray id",  # Cloudflare Ray ID footer
    "enable javascript",
    "browser check",
    "security check",
    "verifying you are human",
    "vshield",
    "one more step",
    "please turn javascript on",
]

# ---------------------------------------------------------------------------
# Stealth JavaScript injected before every page load
# ---------------------------------------------------------------------------

_STEALTH_JS = """
// Remove webdriver flag
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined,
});

// Spoof plugins length (real browsers have plugins)
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const arr = [1, 2, 3, 4, 5];
        arr.__proto__ = Plugin.prototype;
        return arr;
    },
});

// Spoof languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
});

// Hide automation-related chrome properties
window.chrome = {
    runtime: {},
    loadTimes: function() {},
    csi: function() {},
    app: {},
};

// Prevent iframe detection of automation
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) =>
    parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters);

// Spoof hardware concurrency
Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 4,
});

// Spoof device memory
Object.defineProperty(navigator, 'deviceMemory', {
    get: () => 8,
});
"""


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class BrowserCrawlerError(RuntimeError):
    """Raised when all retry attempts are exhausted or browser fails to launch."""


# ---------------------------------------------------------------------------
# Cookie persistence helpers
# ---------------------------------------------------------------------------


def _cookie_path(url: str) -> Path:
    """Return the cookie file path for the given URL's hostname."""
    COOKIE_STORE_DIR.mkdir(parents=True, exist_ok=True)
    host = urlparse(url).hostname or "unknown"
    # Sanitise hostname so it's safe as a filename
    safe = host.replace(".", "_").replace(":", "_")
    return COOKIE_STORE_DIR / f"{safe}.json"


def _load_cookies(url: str) -> list[dict]:
    path = _cookie_path(url)
    if path.exists():
        try:
            cookies = json.loads(path.read_text())
            logger.debug("browser_crawler: loaded %d cookies for %s", len(cookies), url)
            return cookies
        except Exception as exc:
            logger.warning("browser_crawler: failed to load cookies from %s: %s", path, exc)
    return []


def _save_cookies(url: str, cookies: list[dict]) -> None:
    path = _cookie_path(url)
    try:
        path.write_text(json.dumps(cookies, indent=2))
        logger.debug("browser_crawler: saved %d cookies for %s", len(cookies), url)
    except Exception as exc:
        logger.warning("browser_crawler: failed to save cookies to %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Challenge detection
# ---------------------------------------------------------------------------


def _is_challenge_active(html: str) -> bool:
    """Return True if the page content still shows an anti-bot challenge."""
    if not html or len(html.strip()) < 200:
        return True  # suspiciously empty
    lower = html.lower()
    return any(marker in lower for marker in _CHALLENGE_MARKERS)


# ---------------------------------------------------------------------------
# Human-behaviour simulation
# ---------------------------------------------------------------------------


async def _simulate_human(page) -> None:
    """Perform randomised mouse movements, a small scroll, and a timed pause."""
    try:
        vp = page.viewport_size or {"width": 1280, "height": 800}
        w, h = vp["width"], vp["height"]

        # Generate a smooth Bezier-like mouse path across the viewport
        num_points = random.randint(5, 12)
        cx = random.randint(w // 4, 3 * w // 4)
        cy = random.randint(h // 4, 3 * h // 4)
        for i in range(num_points):
            angle = (2 * math.pi * i) / num_points
            rx = random.randint(30, min(120, w // 6))
            ry = random.randint(20, min(80, h // 8))
            tx = int(cx + rx * math.cos(angle) + random.randint(-10, 10))
            ty = int(cy + ry * math.sin(angle) + random.randint(-10, 10))
            tx = max(0, min(tx, w - 1))
            ty = max(0, min(ty, h - 1))
            await page.mouse.move(tx, ty)
            await asyncio.sleep(random.uniform(0.05, 0.20))

        # Scroll down slightly, then back
        scroll_px = random.randint(80, 300)
        await page.mouse.wheel(0, scroll_px)
        await asyncio.sleep(random.uniform(0.3, 0.8))
        await page.mouse.wheel(0, -scroll_px // 2)

    except Exception as exc:
        logger.debug("browser_crawler: human simulation error (non-fatal): %s", exc)

    # Human pause
    delay = random.uniform(HUMAN_DELAY_MIN, HUMAN_DELAY_MAX)
    logger.debug("browser_crawler: human delay %.1fs", delay)
    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Browser / context lifecycle (singleton per process)
# ---------------------------------------------------------------------------

_browser_lock = asyncio.Lock()
_browser_instance = None  # playwright.chromium Browser object
_playwright_instance = None  # Playwright handle (must stay alive)


async def _get_browser():
    """Return the shared Chromium browser, launching it if needed."""
    global _browser_instance, _playwright_instance

    async with _browser_lock:
        if _browser_instance is not None:
            try:
                # Quick liveness check — will raise if browser has crashed
                _ = _browser_instance.contexts
                return _browser_instance
            except Exception:
                logger.warning("browser_crawler: browser instance died, relaunching")
                _browser_instance = None
                _playwright_instance = None

        from playwright.async_api import async_playwright

        logger.info("browser_crawler: launching Chromium browser (headless=%s)", _HEADLESS)
        _playwright_instance = await async_playwright().start()
        launch_options: dict = {
            "headless": _HEADLESS,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-notifications",
                "--disable-popup-blocking",
                "--disable-translate",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        }
        proxy = get_outbound_proxy()
        if proxy:
            launch_options["proxy"] = {"server": proxy}
        _browser_instance = await _playwright_instance.chromium.launch(**launch_options)
        logger.info("browser_crawler: Chromium launched (PID available via browser API)")
        return _browser_instance


async def _new_context(browser, url: str):
    """Create a new browser context with stealth settings and persisted cookies."""
    vp_w, vp_h = random.choice(_VIEWPORTS)
    ua = random.choice(_USER_AGENTS)

    context = await browser.new_context(
        viewport={"width": vp_w, "height": vp_h},
        user_agent=ua,
        locale="en-US",
        timezone_id="America/New_York",
        java_script_enabled=True,
        accept_downloads=False,
        ignore_https_errors=True,
        extra_http_headers={
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "DNT": "1",
        },
    )

    # Inject stealth script on every new document
    await context.add_init_script(_STEALTH_JS)

    # Restore persisted cookies
    cookies = _load_cookies(url)
    if cookies:
        try:
            await context.add_cookies(cookies)
        except Exception as exc:
            logger.warning("browser_crawler: could not restore cookies: %s", exc)

    return context


# ---------------------------------------------------------------------------
# Core fetch implementation
# ---------------------------------------------------------------------------


async def _fetch_once(url: str, context) -> str:
    """
    Open a new page, navigate to url, simulate human behaviour, and return HTML.
    Raises on navigation failure or timeout.
    """
    page = await context.new_page()
    try:
        logger.debug("browser_crawler: navigating to %s", url)
        await page.goto(
            url,
            wait_until="networkidle",
            timeout=PAGE_LOAD_TIMEOUT_MS,
        )
        await _simulate_human(page)
        html = await page.content()
        return html
    finally:
        try:
            await page.close()
        except Exception:
            pass


async def _fetch_with_browser_async(url: str) -> str:
    """
    Internal async implementation of fetch_with_browser.

    Tries up to MAX_RETRIES times:
      1. Navigate to the URL inside a fresh context
      2. Detect whether a challenge is still active
      3. If challenge detected: wait extra time and retry
      4. On success: persist cookies and return HTML
    """
    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    last_html: str | None = None
    last_exc: Exception | None = None

    browser = await _get_browser()

    for attempt in range(1, MAX_RETRIES + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrowserCrawlerError(f"browser_crawler: total timeout ({TOTAL_TIMEOUT_S}s) exceeded for {url}")

        logger.info("browser_crawler: attempt %d/%d for %s", attempt, MAX_RETRIES, url)

        context = await _new_context(browser, url)
        try:
            html = await asyncio.wait_for(
                _fetch_once(url, context),
                timeout=min(remaining, PAGE_LOAD_TIMEOUT_MS / 1000 + 15),
            )
            last_html = html

            if _is_challenge_active(html):
                logger.warning(
                    "browser_crawler: challenge still active on attempt %d for %s",
                    attempt,
                    url,
                )
                if attempt < MAX_RETRIES:
                    extra = random.uniform(CHALLENGE_EXTRA_WAIT_MIN, CHALLENGE_EXTRA_WAIT_MAX)
                    logger.info("browser_crawler: waiting %.1fs before retry", extra)
                    await asyncio.sleep(extra)
                continue  # retry in a new context

            # Success — persist cookies and return
            cookies = await context.cookies()
            _save_cookies(url, cookies)
            logger.info("browser_crawler: success on attempt %d for %s", attempt, url)
            return html

        except TimeoutError as exc:
            last_exc = exc
            logger.warning("browser_crawler: timeout on attempt %d for %s", attempt, url)
        except Exception as exc:
            last_exc = exc
            logger.warning("browser_crawler: error on attempt %d for %s: %s", attempt, url, exc)
        finally:
            try:
                await context.close()
            except Exception:
                pass

    # All retries exhausted
    if last_html is not None:
        # Return whatever we have even if challenge markers are present —
        # caller can inspect; at least it's not empty.
        logger.error(
            "browser_crawler: all %d attempts failed for %s — returning last HTML",
            MAX_RETRIES,
            url,
        )
        return last_html

    raise BrowserCrawlerError(f"browser_crawler: all {MAX_RETRIES} attempts failed for {url}") from last_exc


# ---------------------------------------------------------------------------
# Sync wrapper (public API, usable from sync or async callers)
# ---------------------------------------------------------------------------


def fetch_with_browser(url: str) -> str:
    """
    Return HTML content from a JS-protected page by running a real Chromium
    browser with stealth settings, human simulation, and cookie persistence.

    Works from both synchronous and asynchronous calling contexts.

    Parameters
    ----------
    url : str
        Full URL to fetch (http:// or https://).

    Returns
    -------
    str
        Final HTML after bypassing anti-bot challenges.

    Raises
    ------
    BrowserCrawlerError
        When all retry attempts are exhausted and no usable HTML is available.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We're inside an async context — schedule as a task on a separate
        # thread-bound event loop to avoid nesting issues with Playwright.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_in_new_loop, url)
            return future.result(timeout=TOTAL_TIMEOUT_S + 5)
    else:
        return asyncio.run(_fetch_with_browser_async(url))


def _run_in_new_loop(url: str) -> str:
    """Run the async crawler in a fresh event loop (used from thread pool)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_fetch_with_browser_async(url))
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Graceful shutdown helper (call at process exit if desired)
# ---------------------------------------------------------------------------


async def shutdown_browser() -> None:
    """Close the shared browser instance gracefully."""
    global _browser_instance, _playwright_instance
    async with _browser_lock:
        if _browser_instance:
            try:
                await _browser_instance.close()
            except Exception:
                pass
            _browser_instance = None
        if _playwright_instance:
            try:
                await _playwright_instance.stop()
            except Exception:
                pass
            _playwright_instance = None
    logger.info("browser_crawler: browser shutdown complete")
