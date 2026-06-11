import logging

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": 0xFF0000,
    "high": 0xFF6600,
    "medium": 0xFFAA00,
    "low": 0x00AAFF,
}

ALERT_SEVERITIES = {"critical", "high"}
SYSTEM_COLORS = {
    "info": 0x00AAFF,
    "warning": 0xFFAA00,
    "error": 0xFF3300,
}


async def send_discord_threat_alert(threat) -> None:
    """Send a Discord embed for a new critical/high threat. No-op if webhook not configured."""
    if not settings.discord_webhook_url:
        return
    if (threat.severity or "").lower() not in ALERT_SEVERITIES:
        return

    color = SEVERITY_COLORS.get((threat.severity or "").lower(), 0x808080)
    title = (threat.title or "Unknown threat")[:256]
    description = (threat.content or "")[:300]
    if len(threat.content or "") > 300:
        description += "…"

    fields = []
    if threat.type:
        fields.append({"name": "Type", "value": threat.type, "inline": True})
    if threat.severity:
        fields.append({"name": "Severity", "value": threat.severity.upper(), "inline": True})
    if threat.actor:
        fields.append({"name": "Actor", "value": threat.actor[:100], "inline": True})
    if threat.country:
        fields.append({"name": "Country", "value": threat.country, "inline": True})
    if threat.tags:
        tag_list = ", ".join(threat.tags[:8]) if isinstance(threat.tags, list) else str(threat.tags)
        fields.append({"name": "Tags", "value": tag_list[:200], "inline": False})

    embed = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
    }
    if threat.url:
        embed["url"] = threat.url
    if threat.published_at:
        embed["timestamp"] = threat.published_at.isoformat()

    payload = {
        "username": "CTI Monitor",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092693.png",
        "embeds": [embed],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(settings.discord_webhook_url, json=payload)
            resp.raise_for_status()
        logger.info(f"Discord alert sent for threat: {title[:60]}")
    except Exception as exc:
        logger.warning(f"Discord alert failed: {exc}")


async def send_discord_system_alert(title: str, description: str, level: str = "warning") -> None:
    """Send a non-threat operational alert (forbidden feed, auth issue, etc.)."""
    if not settings.discord_webhook_url:
        return

    color = SYSTEM_COLORS.get((level or "").lower(), 0x808080)
    payload = {
        "username": "CTI Monitor",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092693.png",
        "embeds": [
            {
                "title": (title or "CTI Monitor alert")[:256],
                "description": (description or "")[:1800],
                "color": color,
            }
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(settings.discord_webhook_url, json=payload)
            resp.raise_for_status()
        logger.info("Discord system alert sent: %s", title[:80])
    except Exception as exc:
        logger.warning("Discord system alert failed: %s", exc)
