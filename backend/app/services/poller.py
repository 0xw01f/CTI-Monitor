import asyncio
import calendar
import logging
import re
import time
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.parse import urlparse as _urlparse

import feedparser
import httpx

from ..config import settings
from ..database import SessionLocal
from ..models import Actor, ActorContact, Source, Threat, ThreatLink
from .actor_service import enrich_actor
from .alerting import send_discord_system_alert, send_discord_threat_alert
from .browser_crawler import BrowserCrawlerError, fetch_with_browser
from .content_enrichment import extract_contacts_from_html, extract_full_post
from .graph import build_threat_graph
from .identity import parse_actor_identity
from .kimi import classify_post
from .origin import detect_victim_origin
from .proxy import require_proxy
from .scorer import build_dedup_key, check_noise, classify_threat

# Maps Kimi output types to internal scorer types
_KIMI_TO_INTERNAL: dict[str, str] = {
    "database": "database",
    "access": "access",
    "stealer": "stealer_logs",
    "combo": "credentials",
    "other": "other",
}

logger = logging.getLogger(__name__)

# HTTP codes that indicate Cloudflare or gateway blocking / transient proxy errors
_CF_CODES = {400, 403, 429, 502, 503, 504}

# Backoff delays (seconds) between retry attempts
_RETRY_BACKOFF = [3, 8, 20]

# Strings in a response body that signal an anti-bot / challenge page
_CHALLENGE_MARKERS = (
    "checking your browser",
    "just a moment",
    "ddos protection",
    "please wait",
    "enable javascript",
    "verifying you are human",
    "ray id",
    "vshield",
    "one more step",
)

_STRICT_SIGNAL_HOSTS = {"spear.cx", "www.spear.cx"}

# Source-specific spam terms seen in noisy marketplace sections.
_SPEAR_SPAM_TERMS = (
    "mailer",
    "calling tools",
    "vcc",
    "verified account",
    "aged account",
    "paypal account",
    "payoneer",
    "sms sender",
    "spoof sender",
    "proxies",
    "web development services",
    "bot service",
)

# High-signal terms that usually indicate actionable CTI data/leaks.
_SPEAR_SIGNAL_TERMS = (
    "database",
    "db",
    "breach",
    "breached",
    "leak",
    "leaked",
    "dump",
    "records",
    "users",
    "credentials",
    "combo",
    "stealer",
    "logs",
    "source code",
    "full access",
    "rdp",
    "vpn",
    "shell",
    "exploit",
    "0day",
    "cve-",
)

_WORD_DB_RE = re.compile(r"\bdb\b", re.I)
_AUTH_COOKIE_HOSTS = {"breached.st", "www.breached.st"}
_FORBIDDEN_ALERT_COOLDOWN_SEC = 3600
_FORBIDDEN_ALERT_LAST_SENT: dict[str, float] = {}
_GENERIC_NOISE_TERMS = (
    "mailer",
    "sms sender",
    "spoof sender",
    "verified account",
    "aged account",
    "vcc",
    "proxies",
    "design services",
)


def _source_quality_filter_reason(
    source: Source,
    title: str,
    content: str,
    threat_type: str,
    score: int,
) -> str | None:
    """Return a drop reason for low-value source-specific marketplace noise."""
    host = (urlparse(source.url or "").netloc or "").lower()
    if host not in _STRICT_SIGNAL_HOSTS:
        return None

    text = f"{title}\n{content}".lower()
    spam_hit = next((kw for kw in _SPEAR_SPAM_TERMS if kw in text), None)

    has_signal = any(kw in text for kw in _SPEAR_SIGNAL_TERMS)
    if not has_signal and _WORD_DB_RE.search(text):
        has_signal = True

    if spam_hit and not has_signal:
        return f"spear_spam_term:{spam_hit}"

    # Additional guard: discard weak "other" posts with no clear signal.
    if threat_type == "other" and score < 35 and not has_signal:
        return "spear_low_signal_other"

    return None


def _should_hide_from_public(title: str, content: str, threat_type: str, score: int) -> bool:
    """
    Mark likely noisy/marketplace posts as non-public by default.
    Admin can later approve them for public visibility.
    """
    text = f"{title}\n{content}".lower()
    if any(term in text for term in _GENERIC_NOISE_TERMS):
        return True
    if threat_type == "other" and score < 45:
        return True
    if score < 30:
        return True
    return False


def _headers_for_url(base_headers: dict, url: str) -> dict:
    """Return request headers, adding auth cookie for known protected hosts."""
    headers = dict(base_headers)
    host = (urlparse(url).netloc or "").lower()
    if host in _AUTH_COOKIE_HOSTS and settings.breached_xf_user_cookie:
        cookie_value = settings.breached_xf_user_cookie.strip()
        if not cookie_value.lower().startswith("xf_user="):
            cookie_value = f"xf_user={cookie_value}"
        headers["Cookie"] = cookie_value
    return headers


async def _maybe_alert_forbidden(url: str, status_code: int) -> None:
    """Send throttled Discord alert for forbidden/unauthorized protected feeds."""
    host = (urlparse(url).netloc or "").lower()
    if host not in _AUTH_COOKIE_HOSTS:
        return

    key = f"{host}:{status_code}"
    now = time.monotonic()
    last = _FORBIDDEN_ALERT_LAST_SENT.get(key, 0.0)
    if now - last < _FORBIDDEN_ALERT_COOLDOWN_SEC:
        return
    _FORBIDDEN_ALERT_LAST_SENT[key] = now

    cookie_state = "configured" if settings.breached_xf_user_cookie else "missing"
    await send_discord_system_alert(
        title=f"Feed auth issue: {host} returned {status_code}",
        description=(
            f"Source URL: {url}\n"
            f"HTTP status: {status_code}\n"
            f"xf_user cookie: {cookie_state}\n"
            "The authenticated RSS feed may have expired credentials or invalid session."
        ),
        level="warning",
    )


def _is_valid_feed(feed: feedparser.FeedParserDict, raw_text: str) -> bool:
    """Return True when *feed* looks like a genuine RSS/Atom feed.

    feedparser happily parses HTML (including Cloudflare challenge pages) and
    returns an object with an empty ``entries`` list and no ``version``.
    We consider the response a real feed when ANY of the following hold:

    * ``feed.version`` is non-empty  (e.g. ``'rss20'``, ``'atom10'``)
    * ``feed.entries`` is non-empty
    * The raw text starts with an XML declaration or a known feed root tag

    A challenge / plain-HTML page fails all three checks.
    """
    if feed.version:
        return True
    if feed.entries:
        return True
    # Light structural check on the raw bytes (faster than re-parsing)
    head = raw_text.lstrip()[:200].lower()
    if head.startswith("<?xml") or any(tag in head for tag in ("<rss", "<feed", "<rdf:rdf", "<channel")):
        return True
    return False


# Number of consecutive errors before a source is flagged unstable
_UNSTABLE_THRESHOLD = 3

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Fallback user-agents tried in order when the primary request is blocked
_FALLBACK_HEADERS = [
    {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        ),
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
        "Accept-Language": "en-US,en;q=0.9",
    },
    {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
        "Accept-Language": "en-US,en;q=0.9",
    },
]


def _derive_atom_url(url: str) -> str | None:
    """For MyBB syndication.php RSS URLs, derive the equivalent Atom 1.0 URL.

    MyBB exposes both formats through the same endpoint:
      RSS  → syndication.php?fid=N
      Atom → syndication.php?type=atom1.0&fid=N

    Returns None when the URL is not a recognisable syndication.php endpoint
    or already requests a specific type (so we don't loop).
    """
    parsed = _urlparse(url)
    if "syndication.php" not in parsed.path:
        return None
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    if "type" in params:
        return None  # already specifies a format — don't recurse
    params["type"] = "atom1.0"
    new_query = urlencode(params)
    return parsed._replace(query=new_query).geturl()


async def _http_fetch_feed(
    url: str,
    proxies,
) -> feedparser.FeedParserDict | None:
    """Try fetching *url* as a feed with our rotating UA list.

    Returns a parsed FeedParserDict on success, or None if every attempt
    fails (blocked, timeout, or non-feed response).  Never raises.
    """
    attempts = [HEADERS] + _FALLBACK_HEADERS
    for i, headers in enumerate(attempts):
        if i > 0:
            wait = _RETRY_BACKOFF[min(i - 1, len(_RETRY_BACKOFF) - 1)]
            logger.warning(
                "fetch_rss: attempt %d/%d for %s — waiting %ds (fallback UA)",
                i + 1,
                len(attempts),
                url,
                wait,
            )
            await asyncio.sleep(wait)

        try:
            request_headers = _headers_for_url(headers, url)
            async with httpx.AsyncClient(
                timeout=30, follow_redirects=True, verify=not settings.insecure_ssl, proxies=proxies
            ) as client:
                response = await client.get(url, headers=request_headers)

            if response.status_code in (401, 403):
                await _maybe_alert_forbidden(url, response.status_code)

            if response.status_code in _CF_CODES:
                logger.warning(
                    "fetch_rss: CF/gateway code %d on attempt %d for %s",
                    response.status_code,
                    i + 1,
                    url,
                )
                continue

            response.raise_for_status()
            feed = feedparser.parse(response.text)

            if not _is_valid_feed(feed, response.text):
                body_lower = response.text.lower()
                challenge_hit = next((m for m in _CHALLENGE_MARKERS if m in body_lower), None)
                reason = f"challenge marker '{challenge_hit}'" if challenge_hit else "no feed structure detected"
                logger.warning(
                    "fetch_rss: non-feed response on attempt %d for %s — %s",
                    i + 1,
                    url,
                    reason,
                )
                continue

            if i > 0:
                logger.info(
                    "fetch_rss: recovered on attempt %d (fallback UA) for %s",
                    i + 1,
                    url,
                )
            return feed

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.warning("fetch_rss: network error on attempt %d for %s: %s", i + 1, url, exc)
        except httpx.HTTPStatusError as exc:
            logger.warning("fetch_rss: HTTP error on attempt %d for %s: %s", i + 1, url, exc)

    return None


def _strip_nul(s: str | None) -> str | None:
    """Strip NUL bytes (0x00) that PostgreSQL TEXT columns reject."""
    return s.replace("\x00", "") if s else s


def _sanitize_raw(d: dict) -> dict:
    """Recursively strip NUL bytes from all string values in a dict."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = v.replace("\x00", "")
        elif isinstance(v, dict):
            result[k] = _sanitize_raw(v)
        elif isinstance(v, list):
            result[k] = [i.replace("\x00", "") if isinstance(i, str) else i for i in v]
        else:
            result[k] = v
    return result


def _safe_raw(entry: dict) -> dict:
    """Extract only JSON-serializable fields from a feedparser entry."""
    safe = {}
    for k, v in entry.items():
        if isinstance(v, str | int | float | bool | type(None)):
            safe[k] = v.replace("\x00", "") if isinstance(v, str) else v
        elif isinstance(v, list | tuple) and all(isinstance(i, str) for i in v):
            safe[k] = [i.replace("\x00", "") for i in v]
        else:
            safe[k] = str(v).replace("\x00", "")
    return safe


async def fetch_rss(url: str) -> feedparser.FeedParserDict:
    """Fetch and parse an RSS/Atom feed with a tiered fallback strategy.

    Tier 1 — HTTP with rotating UAs (original URL, RSS/XML format)
    Tier 2 — HTTP with rotating UAs (Atom 1.0 variant, auto-derived for
              MyBB syndication.php endpoints)
    Tier 3 — Playwright browser crawler (bypasses JS/Cloudflare challenges)

    feedparser handles both RSS 2.0 and Atom 1.0 transparently, normalising
    all fields to the same dict structure — no extra conversion needed.
    """
    proxies = require_proxy()

    # --- Tier 1: HTTP fetch of the original URL ---
    logger.info("fetch_rss: tier-1 HTTP fetch for %s", url)
    feed = await _http_fetch_feed(url, proxies)
    if feed is not None:
        return feed

    # --- Tier 2: HTTP fetch of the Atom variant (syndication.php only) ---
    atom_url = _derive_atom_url(url)
    if atom_url:
        logger.warning("fetch_rss: tier-1 failed for %s — trying Atom fallback %s", url, atom_url)
        feed = await _http_fetch_feed(atom_url, proxies)
        if feed is not None:
            logger.info("fetch_rss: recovered via Atom fallback for %s", url)
            return feed

    # --- Tier 3: Playwright browser crawler ---
    # Handles JS challenges (Cloudflare Turnstile, vshield, etc.).
    # Runs in a thread executor so it doesn't block the async event loop.
    target = atom_url or url
    logger.warning("fetch_rss: tiers 1-2 failed — trying browser crawler for %s", target)
    try:
        loop = asyncio.get_event_loop()
        html = await loop.run_in_executor(None, fetch_with_browser, target)
        feed = feedparser.parse(html)
        if _is_valid_feed(feed, html):
            logger.info("fetch_rss: recovered via browser crawler for %s", target)
            return feed
        logger.warning("fetch_rss: browser crawler returned non-feed content for %s", target)
    except BrowserCrawlerError as exc:
        logger.warning("fetch_rss: browser crawler failed for %s: %s", target, exc)
    except Exception as exc:
        logger.warning("fetch_rss: browser crawler unexpected error for %s: %s", target, exc)

    raise RuntimeError(
        f"fetch_rss: all tiers exhausted for {url}" + (f" (also tried Atom: {atom_url})" if atom_url else "")
    )


async def process_entry(entry: feedparser.FeedParserDict, source: Source, db):
    """Insert a single RSS entry. Returns the new Threat object, or None if already exists."""
    external_id = str(entry.get("id") or entry.get("link") or entry.get("title") or "")
    if not external_id:
        return None

    exists = (
        db.query(Threat)
        .filter(
            Threat.source_id == source.id,
            Threat.external_id == external_id,
        )
        .first()
    )
    if exists:
        return None

    title = _strip_nul(entry.get("title", "Unknown")) or "Unknown"

    # Content
    content = ""
    if entry.get("content"):
        content = entry["content"][0].get("value", "")
    elif entry.get("summary"):
        content = entry.get("summary", "")
    content = _strip_nul(content) or ""

    url = _strip_nul(entry.get("link", "")) or ""
    raw_actor = entry.get("author") or entry.get("dc_creator") or None
    actor_identity = parse_actor_identity(raw_actor, source.url)
    actor_name = actor_identity["username"]

    # --- Noise gate: drop low-value content early ---
    noise = check_noise(title, content, actor_name or "")
    if noise["is_noise"]:
        logger.debug("  [NOISE] Dropping '%s' — %s", title[:80], noise["noise_reason"])
        return None

    # Parse publication date (feedparser returns UTC struct_time)
    published_at = None
    if entry.get("published_parsed"):
        try:
            published_at = datetime.utcfromtimestamp(calendar.timegm(entry.published_parsed))
        except Exception:
            pass

    dedup_key = build_dedup_key(title, actor_name or "")

    # --- Dedup gate: drop same title+actor (normalized) already seen ---
    # NOTE: intentionally checks ALL threats including soft-deleted ones so that
    # manually-deleted threats are not re-ingested on the next poll.
    from sqlalchemy import func

    dup = db.query(Threat).filter(func.json_extract_path_text(Threat.raw_data, "dedup_key") == dedup_key).first()
    if dup:
        logger.debug(
            "  [DEDUP] Dropping '%s' — duplicate of #%d (deleted=%s)",
            title[:80],
            dup.id,
            dup.is_deleted,
        )
        return None

    threat_type, severity, score, tags = classify_threat(title, content)
    quality_drop_reason = _source_quality_filter_reason(
        source=source,
        title=title,
        content=content,
        threat_type=threat_type,
        score=score,
    )
    if quality_drop_reason:
        logger.info(
            "  [FILTER] Dropping '%s' from %s — %s",
            title[:80],
            source.name,
            quality_drop_reason,
        )
        return None

    # Kimi refinement: override keyword type when model is confident
    kimi = await classify_post(f"{title}\n{content[:2000]}")
    if kimi["confidence"] >= 0.7 and kimi["type"] != "other":
        threat_type = _KIMI_TO_INTERNAL.get(kimi["type"], threat_type)

    origin = detect_victim_origin(f"{title}\n{content}")

    threat = Threat(
        source_id=source.id,
        external_id=external_id,
        title=title,
        content=content,
        url=url,
        type=threat_type,
        severity=severity,
        score=score,
        actor=actor_name,
        actor_profile_url=actor_identity["profile_url"],
        actor_profile_id=actor_identity["profile_id"],
        country=origin["country"],
        victim_origin_method=origin["method"],
        victim_origin_confidence=origin["confidence"],
        victim_origin_evidence=origin["evidence"],
        tags=tags,
        published_at=published_at,
        is_public=not _should_hide_from_public(title, content, threat_type, score),
        raw_data=_sanitize_raw({**_safe_raw(dict(entry)), "dedup_key": dedup_key}),
    )
    db.add(threat)
    db.flush()

    # Full post capture and link extraction (stored separately).
    # extract_full_post is synchronous (httpx + Playwright) — run it in a
    # thread-pool executor so it doesn't block the async event loop.
    loop = asyncio.get_event_loop()
    full_payload = await loop.run_in_executor(None, extract_full_post, url)
    threat.full_post_html = _strip_nul(full_payload["full_post_html"])
    threat.full_post_text = _strip_nul(full_payload["full_post_text"])
    domains = []
    for link in full_payload["links"]:
        parsed = urlparse(link)
        domains.append(parsed.netloc)
        db.add(
            ThreatLink(
                threat_id=threat.id,
                url=link,
                domain=parsed.netloc,
                link_type="external",
            )
        )

    # Upsert actor
    actor_ref = None
    if actor_name:
        actor = None
        if actor_identity["profile_id"] and actor_identity["source_host"]:
            actor = (
                db.query(Actor)
                .filter(
                    Actor.profile_id == actor_identity["profile_id"],
                    Actor.source_host == actor_identity["source_host"],
                )
                .first()
            )
        if not actor:
            actor = db.query(Actor).filter(Actor.username == actor_name).first()

        if actor:
            actor.post_count += 1
            actor.last_seen = datetime.utcnow()
            actor.profile_url = actor_identity["profile_url"] or actor.profile_url
            actor.profile_id = actor_identity["profile_id"] or actor.profile_id
            actor.source_host = actor_identity["source_host"] or actor.source_host
            history = actor.username_history or []
            if actor_name != actor.username and actor_name not in history:
                history.append(actor.username)
                actor.username_history = history[-25:]
                actor.username = actor_name
            actor_ref = actor
        else:
            actor = Actor(
                username=actor_name,
                profile_url=actor_identity["profile_url"],
                profile_id=actor_identity["profile_id"],
                source_host=actor_identity["source_host"],
                username_history=[],
                platform=source.category or source.type,
                first_seen=published_at or datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
            db.add(actor)
            db.flush()
            actor_ref = actor

    # Extract contacts from the already-fetched post HTML (no extra HTTP call)
    contacts = extract_contacts_from_html(full_payload["full_post_html"])
    if actor_ref:
        for c in contacts:
            existing = (
                db.query(ActorContact)
                .filter(
                    ActorContact.actor_id == actor_ref.id,
                    ActorContact.kind == c["kind"],
                    ActorContact.value == c["value"],
                )
                .first()
            )
            if not existing:
                db.add(
                    ActorContact(
                        actor_id=actor_ref.id,
                        kind=c["kind"],
                        value=c["value"][:300],
                        confidence=float(c["confidence"]),
                    )
                )

    build_threat_graph(
        db=db,
        threat=threat,
        domains=[d for d in domains if d],
        urls=full_payload["links"],
        actor_contacts=contacts,
    )

    # Actor enrichment: reputation, spam detection, specialization, source tracking
    if actor_ref:
        enrich_actor(db, actor_ref, threat)

    db.commit()
    return threat


async def poll_source(source_id: int) -> None:
    db = SessionLocal()
    try:
        source = db.query(Source).filter(Source.id == source_id).first()
        if not source or not source.active:
            return

        logger.info(f"Polling source #{source_id}: {source.name}")

        feed = await fetch_rss(source.url)
        new_threats = []
        for e in feed.entries:
            t = await process_entry(e, source, db)
            if t is not None:
                new_threats.append(t)

        if source.is_unstable:
            logger.info("Source #%d '%s' recovered — clearing unstable flag", source_id, source.name)
        source.last_fetch = datetime.utcnow()
        source.error_count = 0
        source.last_error = None
        source.is_unstable = False
        db.commit()

        logger.info(f"  → {len(new_threats)} new items from '{source.name}'")

        for threat in new_threats:
            await send_discord_threat_alert(threat)

    except Exception as exc:
        logger.error(f"Error polling source #{source_id}: {exc}")
        try:
            source = db.query(Source).filter(Source.id == source_id).first()
            if source:
                new_count = (source.error_count or 0) + 1
                source.error_count = new_count
                source.last_error = str(exc)
                source.last_fetch = datetime.utcnow()

                # Flag as unstable after repeated failures
                if new_count >= _UNSTABLE_THRESHOLD and not source.is_unstable:
                    source.is_unstable = True
                    logger.warning(
                        "Source #%d '%s' marked UNSTABLE after %d consecutive errors",
                        source_id,
                        source.name,
                        new_count,
                    )

                db.commit()
        except Exception:
            pass
    finally:
        db.close()


async def poll_all_sources() -> None:
    db = SessionLocal()
    try:
        source_ids = [s.id for s in db.query(Source).filter(Source.active.is_(True)).all()]
    finally:
        db.close()

    for sid in source_ids:
        await poll_source(sid)
