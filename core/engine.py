"""Async asset discovery workflow for explicitly authorized domains."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Iterable

import aiohttp

from core.fingerprint import fingerprint_host
from core.graph import GraphStore
from core.risk import calculate_risk

logger = logging.getLogger(__name__)
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$")


def normalize_domain(domain: str) -> str:
    """Validate and normalize a domain name (no scheme, path, wildcard, or IP)."""
    value = domain.strip().lower().rstrip(".")
    if "://" in value or "/" in value or "*" in value or not HOST_RE.fullmatch(value):
        raise ValueError("Enter a domain name such as example.com (no URL, path, wildcard, or IP).")
    return value


async def discover_subdomains(domain: str, timeout: float = 8.0) -> list[str]:
    """Use a public certificate-transparency endpoint for passive discovery.

    Use only for domains you own or are explicitly authorized to assess. Network
    policy or the upstream service may limit results. This is not brute forcing.
    """
    domain = normalize_domain(domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    names: set[str] = set()
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, headers={"User-Agent": "pulse-infragraph/1.5"}) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                records = await response.json(content_type=None)
        for record in records if isinstance(records, list) else []:
            for raw in str(record.get("name_value", "")).splitlines():
                host = raw.strip().lower().lstrip("*.")
                if host == domain or host.endswith("." + domain):
                    if HOST_RE.fullmatch(host):
                        names.add(host)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        logger.warning("Certificate transparency lookup failed for %s: %s", domain, exc)
    return sorted(names)


async def scan_domain(domain: str, graph: GraphStore | None = None,
                      concurrency: int = 10) -> dict[str, Any]:
    """Discover, fingerprint, risk-score, and optionally persist assets."""
    domain = normalize_domain(domain)
    hosts = await discover_subdomains(domain)
    if domain not in hosts:
        hosts.insert(0, domain)
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 30)))
    timeout = aiohttp.ClientTimeout(total=8, connect=4)
    async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "pulse-infragraph/1.5 (authorized ASM)"}) as session:
        async def inspect(host: str) -> dict[str, Any]:
            async with semaphore:
                fp = await fingerprint_host(host, session)
            techs = fp.get("technologies", [])
            risk = calculate_risk(host, techs)
            result = {"domain": domain, "subdomain": host, "risk": risk, "fingerprint": fp}
            if graph and graph.available:
                try:
                    graph.upsert_asset(domain, host, risk, techs)
                except Exception:
                    logger.exception("Could not persist %s to Neo4j", host)
            return result
        results = await asyncio.gather(*(inspect(host) for host in hosts), return_exceptions=True)
    assets = []
    for item in results:
        if isinstance(item, Exception):
            logger.warning("Asset inspection failed: %s", item)
        else:
            assets.append(item)
    return {"domain": domain, "assets": assets, "count": len(assets)}
