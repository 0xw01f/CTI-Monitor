import json
import logging
import random
import re
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from .browser_crawler import _HEADLESS, _STEALTH_JS, _USER_AGENTS, COOKIE_STORE_DIR
from .content_enrichment import POST_SELECTORS
from .proxy import get_outbound_proxy

logger = logging.getLogger(__name__)

EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

_CHALLENGE_MARKERS = (
    "checking your browser",
    "just a moment",
    "ddos protection",
    "verifying you are human",
    "ray id",
    "vshield",
)

_VIEWPORTS = [
    (1280, 800),
    (1366, 768),
    (1440, 900),
    (1920, 1080),
]


# ---------------------------------------------------------------------------
# JS anonymization injected into the live DOM before screenshotting
# ---------------------------------------------------------------------------

_ANONYMIZE_JS = r"""
(function(actorName, sourceName, domainSLD) {

    // ── 1. Build master PII regex ────────────────────────────────────────────
    var RAW = [
        '[\\w.+\\-]+@[\\w\\-]+\\.[a-z]{2,}',               // e-mail
        'https?:\\/\\/[^\\s<>"\']+',                         // any URL
        't\\.me\\/[\\w\\-]+',                                // t.me/x
        'telegram[\\s:.\\/]+[\\w@][\\w.@\\-]*',              // telegram: x
        '@[\\w][\\w\\-\\.]{2,}',                             // @handle
        'tox\\s*[:\\-]?\\s*[0-9A-Fa-f]{30,}',
        'session\\s*[:\\-]?\\s*[0-9A-Fa-f]{60,}',
        'wickr\\s*[:\\-]?\\s*[\\w.]+',
        'jabber\\s*[:\\-]?\\s*[\\w@.]+',
        'xmpp\\s*[:\\-]?\\s*[\\w@.]+',
        'icq\\s*[:#]?\\s*\\d{5,}',
        'discord\\s*[:\\-]?\\s*[\\w#.]+',
        'matrix\\s*[:\\-]?\\s*@[\\w.\\-]+:[\\w.\\-]+',
        'signal\\s*[:\\-]?\\s*[\\w@.+\\-]+',
        'bc1[a-zA-HJ-NP-Z0-9]{25,62}',                      // BTC bech32
        '[13][a-km-zA-HJ-NP-Z1-9]{25,34}',                  // BTC legacy
        '0x[0-9a-fA-F]{40}',                                 // ETH
        '4[0-9AB][1-9A-HJ-NP-Za-km-z]{90,}',                // XMR
        'T[A-Za-z1-9]{33}',                                  // TRX
        'L[a-km-zA-HJ-NP-Z1-9]{33}',                        // LTC
        '(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)',
        '\\+\\d[\\d\\s\\-\\.()]{6,}\\d',
    ];

    function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

    function pushName(s) {
        if (!s || s.trim().length < 2) return;
        var base = s.trim();
        RAW.push(esc(base));
        var noExt = base.replace(/\.[a-z]{2,}$/i, '');
        if (noExt !== base && noExt.length >= 2) RAW.push(esc(noExt));
    }
    pushName(actorName); pushName(sourceName); pushName(domainSLD);

    var MASTER = new RegExp(RAW.join('|'), 'gi');

    // ── 2. Blur helper ───────────────────────────────────────────────────────
    function blurEl(el, px) {
        if (!el || el === document.body || el === document.documentElement) return;
        var v = 'blur(' + (px || 8) + 'px)';
        el.style.setProperty('filter', v, 'important');
        el.style.setProperty('-webkit-filter', v, 'important');
        el.style.setProperty('user-select', 'none', 'important');
        el.style.setProperty('pointer-events', 'none', 'important');
    }

    // ── 3. CODE / PRE blocks — blur entirely (these are data dump samples) ───
    // Deliberately NOT blockquote / quote divs — too risky on unknown forum themes.
    document.querySelectorAll('pre, code').forEach(function(el) { blurEl(el); });

    // ── 4. Walk every text node and inline-blur regex matches ─────────────────
    // No block-level escalation at all — we only blur the exact matched characters.
    // This prevents any risk of blurring an entire post body.
    var SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'PRE', 'CODE']);

    var walker = document.createTreeWalker(
        document.body, NodeFilter.SHOW_TEXT,
        { acceptNode: function(n) {
            return SKIP.has((n.parentElement || {}).tagName || '')
                ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
        }}
    );
    var textNodes = [];
    var tn;
    while ((tn = walker.nextNode())) textNodes.push(tn);

    textNodes.forEach(function(node) {
        var text = node.nodeValue;
        if (!text || !text.trim()) return;
        MASTER.lastIndex = 0;
        if (!MASTER.test(text)) return;
        MASTER.lastIndex = 0;

        var frag = document.createDocumentFragment();
        var last = 0, m;
        while ((m = MASTER.exec(text)) !== null) {
            if (m.index > last)
                frag.appendChild(document.createTextNode(text.slice(last, m.index)));
            var s = document.createElement('span');
            s.style.cssText =
                'filter:blur(8px) !important;-webkit-filter:blur(8px) !important;' +
                'display:inline-block;user-select:none;pointer-events:none';
            s.textContent = m[0];
            frag.appendChild(s);
            last = MASTER.lastIndex;
            if (last === 0) break;
        }
        if (last < text.length)
            frag.appendChild(document.createTextNode(text.slice(last)));
        MASTER.lastIndex = 0;
        if (node.parentNode) node.parentNode.replaceChild(frag, node);
    });

    // ── 5. Messenger-domain links ────────────────────────────────────────────
    var BLUR_DOMAINS = [
        't.me', 'telegram.me', 'telegram.dog', 'tox.chat', 'wickr.com',
        'jabber.', 'session.', 'icq.com', 'matrix.to', 'discord.gg', 'signal.me',
    ];
    document.querySelectorAll('a[href]').forEach(function(a) {
        var href = (a.getAttribute('href') || '').toLowerCase();
        if (BLUR_DOMAINS.some(function(d) { return href.indexOf(d) !== -1; }))
            blurEl(a);
    });

    // ── 6. Avatar images only (very conservative) ─────────────────────────────
    document.querySelectorAll(
        'img[src*="/avatar/"], img[src*="/avatars/"], img[src*="avatar_"], ' +
        'img[src*="/userpic/"], img[src*="userpic_"]'
    ).forEach(function(img) { blurEl(img, 10); });

})(ACTOR_PLACEHOLDER, SOURCE_PLACEHOLDER, DOMAIN_PLACEHOLDER);
"""


def _extract_sld(url: str) -> str:
    """Extract the second-level domain (e.g. 'darkforums' from 'darkforums.net')."""
    try:
        host = urlparse(url).hostname or ""
        host = re.sub(r"^www\.", "", host)  # strip leading www.
        parts = host.split(".")
        # Return the SLD (second-to-last part if >1 part, else first part)
        return parts[-2] if len(parts) >= 2 else parts[0]
    except Exception:
        return ""


def evidence_exists(public_path: str | None) -> bool:
    if not public_path:
        return False
    name = Path(public_path).name
    return (EVIDENCE_DIR / name).exists()


def _load_cookies_sync(url: str) -> list[dict]:
    host = urlparse(url).hostname or "unknown"
    safe = host.replace(".", "_").replace(":", "_")
    path = COOKIE_STORE_DIR / f"{safe}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return []


def ensure_post_screenshot(
    url: str | None,
    threat_id: int,
    actor: str | None = None,
    source_name: str | None = None,
    force: bool = False,
) -> str | None:
    if not url:
        return None

    # Check for existing screenshot (JPEG first, then legacy PNG)
    output_jpg = EVIDENCE_DIR / f"threat_{threat_id}.jpg"
    output_png = EVIDENCE_DIR / f"threat_{threat_id}.png"
    if not force:
        if output_jpg.exists():
            return f"/evidence/{output_jpg.name}"
        if output_png.exists():
            return f"/evidence/{output_png.name}"

    # Always save new captures as JPEG
    output = output_jpg

    # Derive the second-level domain from the URL directly (most reliable forum-name source)
    domain_sld = _extract_sld(url)

    try:
        with sync_playwright() as p:
            launch_kwargs: dict = {
                "headless": _HEADLESS,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-infobars",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-extensions",
                    "--disable-notifications",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            }
            proxy = get_outbound_proxy()
            if proxy:
                launch_kwargs["proxy"] = {"server": proxy}

            browser = p.chromium.launch(**launch_kwargs)

            vp_w, vp_h = random.choice(_VIEWPORTS)
            context = browser.new_context(
                viewport={"width": vp_w, "height": vp_h},
                user_agent=random.choice(_USER_AGENTS),
                locale="en-US",
                timezone_id="America/New_York",
                ignore_https_errors=True,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "DNT": "1",
                },
            )
            context.add_init_script(_STEALTH_JS)

            cookies = _load_cookies_sync(url)
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception:
                    pass

            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=45000)

            content_lower = page.content().lower()
            if any(m in content_lower for m in _CHALLENGE_MARKERS):
                logger.debug("screenshot: challenge page detected for %s, waiting...", url)
                page.wait_for_timeout(8000)

            for selector in POST_SELECTORS:
                locator = page.locator(selector).first
                if locator.count() == 0:
                    continue
                if not locator.is_visible(timeout=2000):
                    continue

                text = locator.inner_text(timeout=3000)
                if len((text or "").strip()) < 40:
                    continue

                # Inject anonymization JS before screenshotting
                try:
                    actor_literal = json.dumps(actor or "")
                    source_literal = json.dumps(source_name or "")
                    domain_literal = json.dumps(domain_sld or "")
                    js = (
                        _ANONYMIZE_JS.replace("ACTOR_PLACEHOLDER", actor_literal)
                        .replace("SOURCE_PLACEHOLDER", source_literal)
                        .replace("DOMAIN_PLACEHOLDER", domain_literal)
                    )
                    page.evaluate(js)
                    page.wait_for_timeout(300)  # let repaint settle
                except Exception as e:
                    logger.warning("screenshot: anonymize JS failed: %s", e)

                # Save as compressed JPEG (quality 72 = good visual / ~5-10× smaller than PNG)
                locator.screenshot(path=str(output), type="jpeg", quality=72)
                browser.close()
                logger.info(
                    "screenshot: captured threat #%d → %s (domain=%s)",
                    threat_id,
                    output.name,
                    domain_sld,
                )
                return f"/evidence/{output.name}"

            browser.close()
    except Exception as exc:
        logger.warning("screenshot: failed for threat #%d (%s): %s", threat_id, url, exc)
        return None

    return None
