"""Information disclosure checks — commonly-exposed sensitive paths and banners."""

import requests
from urllib.parse import urljoin

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


def check_information_disclosure(response, base_url: str) -> list:
    findings = []

    for path in SENSITIVE_PATHS:
        test_url = urljoin(base_url, path)
        try:
            r = requests.get(test_url, timeout=6, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                findings.append({
                    "category": "disclosure",
                    "id": f"exposed-path-{path.replace('/', '_')}",
                    "severity": "high",
                    "message": f"Potentially sensitive path is publicly accessible: {test_url} "
                               f"(HTTP {r.status_code})",
                })
        except requests.exceptions.RequestException:
            continue

    return findings
