import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..config import settings
from .browser_crawler import BrowserCrawlerError, fetch_with_browser
from .proxy import require_proxy

logger = logging.getLogger(__name__)

POST_SELECTORS = [
    "div.post_body",
    "div[id^='pid_'] div.post_body",
    "div[id^='post_'] div.post_body",
    "article.post",
    "div.post",
]

CONTACT_PATTERNS = {
    "telegram": re.compile(r"(?:t\.me/|@)([A-Za-z0-9_]{4,})", re.IGNORECASE),
    "tox": re.compile(r"\b[a-f0-9]{76}\b", re.IGNORECASE),
    "session": re.compile(r"\b05[a-f0-9]{64}\b", re.IGNORECASE),
    "jabber": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE),
    "icq": re.compile(r"\bicq[:\s]*([0-9]{5,12})\b", re.IGNORECASE),
}

# Common email domains that are never Telegram handles — used to filter false positives.
_TELEGRAM_EXCLUDES = {
    "gmail",
    "hotmail",
    "yahoo",
    "outlook",
    "live",
    "protonmail",
    "icloud",
    "mail",
    "email",
    "example",
    "domain",
    "test",
    "admin",
    "support",
    "info",
    "contact",
    "help",
    "noreply",
    "no-reply",
    "webmaster",
    "postmaster",
    "idea",
    "inea",
    "gob",
    "gov",
    "edu",
    "ac",
    "org",
}

# If a single post yields more than this many regex matches for a given kind,
# treat it as a data-leak / victim list rather than actor contacts.
_CONTACT_BURST_LIMIT = 8

# Map the `title` attribute of social icon anchors to a contact kind
_SOCIAL_ICON_TITLES: dict[str, str] = {
    "session id": "session",
    "qtox id": "tox",
    "tox id": "tox",
    "telegram": "telegram",
    "jabber": "jabber",
    "xmpp": "jabber",
    "icq": "icq",
    "wickr": "wickr",
    "signal": "signal",
    "discord": "discord",
    "email": "email",
}


# HTTP status codes that indicate a JS-based anti-bot wall or transient proxy error
_BLOCKED_CODES = {403, 429, 502, 503, 504}


_FETCH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
}


def fetch_html(url: str) -> str | None:
    """Fetch HTML via httpx; falls back to the Playwright browser on blocks."""
    proxies = require_proxy()
    blocked = False
    try:
        with httpx.Client(
            timeout=25.0,
            follow_redirects=True,
            verify=not settings.insecure_ssl,
            proxies=proxies,
        ) as client:
            r = client.get(url, headers=_FETCH_HEADERS)
            if r.status_code in _BLOCKED_CODES:
                blocked = True
            else:
                r.raise_for_status()
                # Quick heuristic: if the page looks like a challenge, use browser
                body_lower = r.text.lower()
                if any(m in body_lower for m in ("checking your browser", "just a moment", "ddos protection")):
                    blocked = True
                else:
                    return r.text
    except Exception:
        blocked = True

    if blocked:
        logger.debug("fetch_html: httpx blocked for %s — falling back to browser crawler", url)
        try:
            return fetch_with_browser(url)
        except BrowserCrawlerError as exc:
            logger.warning("fetch_html: browser crawler also failed for %s: %s", url, exc)
            return None

    return None


def extract_full_post(url: str | None) -> dict:
    if not url:
        return {"full_post_html": None, "full_post_text": None, "links": []}

    html = fetch_html(url)
    if not html:
        return {"full_post_html": None, "full_post_text": None, "links": []}

    soup = BeautifulSoup(html, "html.parser")
    post_node = None
    for selector in POST_SELECTORS:
        candidate = soup.select_one(selector)
        if candidate and candidate.get_text(strip=True):
            post_node = candidate
            break

    node = post_node or soup
    text = node.get_text("\n", strip=True)
    node_html = str(node)

    links = []
    for a in node.select("a[href]"):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        absolute = urljoin(url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        links.append(absolute)

    dedup = sorted(set(links))
    return {
        "full_post_html": node_html[:200000],
        "full_post_text": text[:200000],
        "links": dedup[:1000],
    }


def extract_contacts_from_html(html: str | None) -> list[dict]:
    """
    Extract actor contact info from post HTML that has already been fetched.
    Reads two sources without any extra HTTP request:
      1. <a title="Session ID" href="05…"> style social icon anchors
      2. Regex patterns over the visible text (Telegram handles, Tox IDs, etc.)
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    contacts: list[dict] = []

    # --- Source 1: social icon anchors (href = raw value, title = kind) ---
    for a in soup.select(".post_usersocialicons a[title], .post_social a[title], .post_author a[title]"):
        title_raw = (a.get("title") or "").strip().lower()
        kind = _SOCIAL_ICON_TITLES.get(title_raw)
        if not kind:
            continue
        value = (a.get("href") or "").strip()
        if not value or value.startswith("http"):
            # href sometimes links to an external URL wrapper — skip
            continue
        contacts.append({"kind": kind, "value": value, "confidence": 0.90})

    # --- Source 2: regex scan over visible text ---
    text = soup.get_text("\n", strip=True)
    raw_regex_contacts: list[dict] = []
    for kind, pattern in CONTACT_PATTERNS.items():
        for m in pattern.findall(text):
            value = m if isinstance(m, str) else (m[0] if m else "")
            value = (value or "").strip()
            if not value:
                continue
            if kind == "telegram":
                if value.lower() in _TELEGRAM_EXCLUDES:
                    continue
                if not value.startswith("@"):
                    value = f"@{value}"
            raw_regex_contacts.append({"kind": kind, "value": value, "confidence": 0.75})

    # Volume gate: if a single post yields a burst of the same kind,
    # treat it as a victim list / data-leak and drop that kind entirely.
    kind_counts: dict[str, int] = {}
    for c in raw_regex_contacts:
        kind_counts[c["kind"]] = kind_counts.get(c["kind"], 0) + 1
    for c in raw_regex_contacts:
        if kind_counts.get(c["kind"], 0) <= _CONTACT_BURST_LIMIT:
            contacts.append(c)

    # Deduplicate (keep highest confidence per kind+value)
    seen: dict[tuple, dict] = {}
    for c in contacts:
        key = (c["kind"], c["value"].lower())
        if key not in seen or c["confidence"] > seen[key]["confidence"]:
            seen[key] = c
    return list(seen.values())[:200]


def extract_actor_contacts(profile_url: str | None) -> list[dict]:
    if not profile_url:
        return []
    html = fetch_html(profile_url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n", strip=True)

    contacts = []
    for kind, pattern in CONTACT_PATTERNS.items():
        matches = pattern.findall(text)
        if len(matches) > _CONTACT_BURST_LIMIT:
            continue
        for m in matches:
            value = m if isinstance(m, str) else (m[0] if m else "")
            value = (value or "").strip()
            if not value:
                continue
            if kind == "telegram":
                if value.lower() in _TELEGRAM_EXCLUDES:
                    continue
                if not value.startswith("@"):
                    value = f"@{value}"
            contacts.append({"kind": kind, "value": value, "confidence": 0.75})

    seen = set()
    uniq = []
    for c in contacts:
        key = (c["kind"], c["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq[:200]
