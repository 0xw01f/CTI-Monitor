"""
Social media auto-poster.

Currently supports Bluesky (AT Protocol). X/Twitter can be added later.
"""

import logging

from atproto import Client
from atproto.exceptions import AtProtocolError
from starlette.concurrency import run_in_threadpool

from ..config import settings

logger = logging.getLogger(__name__)


def _build_post_url(handle: str, uri: str) -> str:
    """Build a human-readable Bluesky post URL from an at:// URI."""
    # at://did:plc:xxx/app.bsky.feed.post/rkey
    try:
        rkey = uri.split("/")[-1]
        return f"https://bsky.app/profile/{handle}/post/{rkey}"
    except Exception:
        return f"https://bsky.app/profile/{handle}"


def _publish_sync(text: str, image_path: str | None, handle: str, app_password: str) -> dict:
    """Synchronous Bluesky publish helper (runs in threadpool)."""
    client = Client()
    client.login(handle, app_password)

    image_bytes = None
    if image_path:
        try:
            with open(image_path, "rb") as f:
                image_bytes = f.read()
        except Exception as exc:
            logger.warning("Could not read screenshot for Bluesky post: %s", exc)

    if image_bytes:
        upload = client.upload_blob(image_bytes)
        embed = {
            "$type": "app.bsky.embed.images#main",
            "images": [
                {
                    "alt": "Threat evidence screenshot",
                    "image": upload.blob,
                }
            ],
        }
        response = client.send_post(text=text, embed=embed)
    else:
        response = client.send_post(text=text)

    post_url = _build_post_url(handle, response.uri)
    return {"ok": True, "post_url": post_url, "detail": "Published"}


async def publish_to_bluesky(text: str, image_path: str | None = None) -> dict:
    """
    Publish a text post to Bluesky.

    Returns {"ok": bool, "post_url": str | None, "detail": str}.
    """
    if not settings.bluesky_enabled:
        return {"ok": False, "post_url": None, "detail": "Bluesky is not enabled"}
    if not settings.bluesky_handle or not settings.bluesky_app_password:
        return {"ok": False, "post_url": None, "detail": "Bluesky credentials not configured"}

    try:
        return await run_in_threadpool(
            _publish_sync,
            text,
            image_path,
            settings.bluesky_handle,
            settings.bluesky_app_password,
        )
    except AtProtocolError as exc:
        logger.warning("Bluesky publish failed: %s", exc)
        return {"ok": False, "post_url": None, "detail": f"Bluesky error: {exc}"}
    except Exception as exc:
        logger.warning("Bluesky publish failed: %s", exc)
        return {"ok": False, "post_url": None, "detail": f"Unexpected error: {exc}"}
