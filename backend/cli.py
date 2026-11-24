# Copyright (c) 2026 MR CYBER PULSE
# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line entrypoint for authorized ASM scans."""
from __future__ import annotations

import argparse
import asyncio
import json

from backend.core.engine import normalize_domain, scan_domain


async def main_async(domain: str) -> dict:
    """Run a scan and print the JSON result without the Streamlit UI."""
    normalized = normalize_domain(domain)
    return await scan_domain(normalized)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a pulse-infragraph scan for an authorized domain.")
    parser.add_argument("domain", help="Root domain to analyze, such as example.com")
    args = parser.parse_args()
    result = asyncio.run(main_async(args.domain))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
