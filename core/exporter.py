"""Async, conservative technology fingerprinting over HTTP(S)."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=8, connect=4)


def _detect_technologies(headers: dict[str, str], body: str) -> list[str]:
    """Infer a small set of technologies from response headers and HTML markers."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    text = body.lower()
    found: set[str] = set()
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if "cloudflare" in server or "cf-ray" in h or "cloudflare" in h.get("via", ""):
        found.add("Cloudflare")
    if "wordpress" in text or "wp-content" in text or "wp-json" in text:
        found.add("WordPress")
    if any(key.startswith("x-amz-") for key in h) or "amazonaws.com" in h.get("x-amz-cf-id", ""):
        found.add("AWS")
    if "nginx" in server:
        found.add("Nginx")
    if "react" in text and ("data-reactroot" in text or "__react" in text or "react-dom" in text):
        found.add("React")
    if "aws" in powered:
        found.add("AWS")
    if "apache" in server:
        found.add("Apache")
    if "iis" in server or "microsoft-iis" in server:
        found.add("IIS")
    if "django" in text or "djano" in text:
        found.add("Django")
    if "flask" in powered or "flask" in text:
        found.add("Flask")
    if "fastapi" in powered or "fastapi" in text or "/docs" in text:
        found.add("FastAPI")
    if "express" in powered or "nodejs" in powered or "express" in text:
        found.add("Node.js")
    return sorted(found)


async def fingerprint_url(url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    """Fetch a URL once and return its URL, status, technologies, and error if any."""
    try:
        async with session.get(url, allow_redirects=True) as response:
            body = await response.text(errors="ignore")
            return {
                "url": url,
                "status": response.status,
                "final_url": str(response.url),
                "technologies": _detect_technologies(dict(response.headers), body[:500_000]),
                "headers": dict(response.headers),
            }
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        logger.debug("Fingerprint failed for %s: %s", url, exc)
        return {"url": url, "status": None, "technologies": [], "error": str(exc)}


async def fingerprint_host(host: str, session: aiohttp.ClientSession | None = None) -> dict[str, Any]:
    """Try HTTPS first, then HTTP, using a shared session when provided."""
    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "pulse-infragraph/1.5 (authorized ASM)"})
    assert session is not None
    try:
        result = await fingerprint_url(f"https://{host}", session)
        if result.get("status") is None:
            result = await fingerprint_url(f"http://{host}", session)
        result["host"] = host
        return result
    finally:
        if own_session:
            await session.close()

