"""Conservative HTTP(S) technology fingerprinting."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=8, connect=4)


def _detect_technologies(headers: dict[str, str], body: str) -> list[str]:
    normalized_headers = {key.lower(): value.lower() for key, value in headers.items()}
    text = body.lower()
    found: set[str] = set()
    server = normalized_headers.get("server", "")
    powered = normalized_headers.get("x-powered-by", "")

    if "cloudflare" in server or "cf-ray" in normalized_headers:
        found.add("Cloudflare")
    if any(marker in text for marker in ("wordpress", "wp-content", "wp-json")):
        found.add("WordPress")
    if any(key.startswith("x-amz-") for key in normalized_headers):
        found.add("AWS")
    if "nginx" in server:
        found.add("Nginx")
    if "apache" in server:
        found.add("Apache")
    if "iis" in server or "microsoft-iis" in server:
        found.add("IIS")
    if "react" in text and any(marker in text for marker in ("data-reactroot", "__react", "react-dom")):
        found.add("React")
    if "aws" in powered:
        found.add("AWS")
    if "django" in text:
        found.add("Django")
    if "flask" in powered or "flask" in text:
        found.add("Flask")
    if "fastapi" in powered or "fastapi" in text:
        found.add("FastAPI")
    if "express" in powered or "nodejs" in powered:
        found.add("Node.js")
    return sorted(found)


async def fingerprint_url(url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
    """Request one URL and return bounded response metadata."""
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


async def fingerprint_host(
    host: str, session: aiohttp.ClientSession | None = None
) -> dict[str, Any]:
    """Try HTTPS, then HTTP if TLS connection fails."""
    own_session = session is None
    if own_session:
        session = aiohttp.ClientSession(
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "pulse-infragraph/1.5 (authorized ASM)"},
        )
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
