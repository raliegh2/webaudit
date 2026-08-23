"""Information disclosure checks — commonly-exposed sensitive paths and banners."""

import uuid
import requests
from urllib.parse import urlparse

SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".git/HEAD",
    "wp-config.php.bak",
    "config.php.bak",
    ".DS_Store",
    "backup.zip",
    ".htaccess",
    "server-status",
    "phpinfo.php",
]


def _root_url(base_url: str, path: str) -> str:
    """Build a URL for `path` relative to the site's domain root, regardless
    of what path segment base_url itself points at. urljoin() alone resolves
    relative to base_url's existing path (e.g. /blog/) rather than the root,
    which silently checks the wrong location on any non-root target."""
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/{path.lstrip('/')}"


def check_information_disclosure(response, base_url: str) -> list:
    findings = []

    # Soft-404 baseline: some servers (SPAs, catch-all routes) return HTTP 200
    # for any path, which would otherwise make every "sensitive path" check
    # below a false positive. Probe a definitely-nonexistent path first and
    # compare status/length against it before trusting a 200 on a real check.
    baseline_status = None
    baseline_length = None
    try:
        probe_path = f"__webaudit_nonexistent_{uuid.uuid4().hex[:12]}__"
        baseline_url = _root_url(base_url, probe_path)
        baseline = requests.get(baseline_url, timeout=6, allow_redirects=False)
        baseline_status = baseline.status_code
        baseline_length = len(baseline.content)
    except requests.exceptions.RequestException:
        pass  # If the baseline probe fails, fall back to a plain 200 check below.

    soft_404_detected = baseline_status == 200

    for path in SENSITIVE_PATHS:
        test_url = _root_url(base_url, path)
        try:
            r = requests.get(test_url, timeout=6, allow_redirects=False)
            if r.status_code != 200 or len(r.content) == 0:
                continue

            if soft_404_detected and len(r.content) == baseline_length:
                # Same status and same body length as the known-bogus path —
                # almost certainly a catch-all response, not a real exposure.
                continue

            findings.append({
                "category": "disclosure",
                "id": f"exposed-path-{path.replace('/', '_')}",
                "severity": "high",
                "message": f"Potentially sensitive path is publicly accessible: {test_url} "
                           f"(HTTP {r.status_code})"
                           + (" [note: this server returns HTTP 200 for unknown paths; "
                              "verify manually before treating as confirmed]" if soft_404_detected else ""),
            })
        except requests.exceptions.RequestException:
            continue

    return findings
