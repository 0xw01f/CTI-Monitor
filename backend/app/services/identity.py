import html
import re
from urllib.parse import parse_qs, urljoin, urlparse

ANCHOR_RE = re.compile(r"<a[^>]+href=['\"]([^'\"]+)['\"][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")


def strip_tags(value: str | None) -> str:
    if not value:
        return ""
    cleaned = TAG_RE.sub("", value)
    return html.unescape(cleaned).strip()


def parse_actor_identity(raw_actor: str | None, source_url: str | None) -> dict:
    base_host = urlparse(source_url or "").netloc or None
    actor_username = strip_tags(raw_actor)
    actor_profile_url: str | None = None
    actor_profile_id: str | None = None

    if raw_actor:
        m = ANCHOR_RE.search(raw_actor)
        if m:
            href, label = m.group(1), m.group(2)
            actor_profile_url = urljoin(source_url or "", href)
            actor_username = strip_tags(label) or actor_username

            parsed = urlparse(actor_profile_url)
            qs = parse_qs(parsed.query)
            uid = qs.get("uid", [None])[0]
            if uid:
                actor_profile_id = str(uid)

    return {
        "username": actor_username or None,
        "profile_url": actor_profile_url,
        "profile_id": actor_profile_id,
        "source_host": base_host,
    }
