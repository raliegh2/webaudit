#!/usr/bin/env python3
"""
webaudit.py — Passive/configuration-level web application security auditor.

Performs non-intrusive checks against one or more targets:
  - HTTP security header analysis
  - SSL/TLS certificate & protocol checks
  - Cookie flag auditing
  - CORS misconfiguration detection
  - Information disclosure checks (server banners, exposed sensitive paths)

Produces a weighted risk score (0-100) and letter grade (A-F) per target,
exportable as text, JSON, or HTML.

This tool is strictly passive: it does not attempt exploitation, brute force,
or any action beyond standard HTTP(S) requests a browser would make. Only use
against systems you own or are explicitly authorized to test.
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from modules.headers_check import check_security_headers
from modules.tls_check import check_tls
from modules.cookie_check import check_cookies
from modules.cors_check import check_cors
from modules.disclosure_check import check_information_disclosure
from modules.report import build_report, export_text, export_json, export_html
from modules.scoring import score_findings


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def audit_target(target: str, timeout: int = 10) -> dict:
    """Run all passive checks against a single target and return a result dict."""
    url = normalize_target(target)
    parsed = urlparse(url)
    host = parsed.hostname

    result = {
        "target": target,
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "errors": [],
    }

    response = None
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError as e:
        result["errors"].append(f"SSL error connecting to {url}: {e}")
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"Could not connect to {url}: {e}")

    if response is not None:
        result["findings"].extend(check_security_headers(response))
        result["findings"].extend(check_cookies(response))
        result["findings"].extend(check_cors(response, url))
        result["findings"].extend(check_information_disclosure(response, url))

    if parsed.scheme == "https" and host:
        port = parsed.port or 443
        result["findings"].extend(check_tls(host, port))

    result["score"], result["grade"] = score_findings(result["findings"])
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Passive web application security auditor (webaudit)"
    )
    parser.add_argument("target", nargs="?", help="Single target URL or hostname")
    parser.add_argument(
        "--targets-file", "-f", help="Path to a file with one target per line"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Report output format (default: text)",
    )
    parser.add_argument("--output", "-o", help="Write report to this file instead of stdout")
    parser.add_argument(
        "--timeout", type=int, default=10, help="Per-request timeout in seconds"
    )
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets_file:
        with open(args.targets_file) as fh:
            targets.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))

    if not targets:
        parser.error("Provide a target or --targets-file")

    results = [audit_target(t, timeout=args.timeout) for t in targets]
    report = build_report(results)

    if args.format == "json":
        output = export_json(report)
    elif args.format == "html":
        output = export_html(report)
    else:
        output = export_text(report)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
