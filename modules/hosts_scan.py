"""Hosts file tampering detection."""

import platform

KNOWN_SAFE_ENTRIES = {"localhost", "127.0.0.1", "::1", "broadcasthost"}

SUSPICIOUS_TARGET_KEYWORDS = [
    "microsoft.com", "windowsupdate.com", "avast.com", "avg.com",
    "kaspersky.com", "malwarebytes.com", "mcafee.com", "norton.com",
    "virustotal.com",
]


def _hosts_path() -> str:
    if platform.system() == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"


def scan_hosts_file() -> list:
    findings = []
    path = _hosts_path()

    try:
        with open(path) as fh:
            lines = fh.readlines()
    except (FileNotFoundError, PermissionError) as e:
        findings.append({
            "category": "hosts",
            "id": "hosts-file-unreadable",
            "severity": "info",
            "message": f"Could not read hosts file at {path}: {e}",
        })
        return findings

    entry_count = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, *hostnames = parts
        entry_count += 1

        for hostname in hostnames:
            if hostname.lower() in KNOWN_SAFE_ENTRIES:
                continue
            if any(kw in hostname.lower() for kw in SUSPICIOUS_TARGET_KEYWORDS):
                findings.append({
                    "category": "hosts",
                    "id": f"hosts-hijack-{hostname}",
                    "severity": "critical",
                    "message": f"Hosts file redirects '{hostname}' -> {ip}. "
                               f"This is commonly used to block security vendor updates or "
                               f"redirect traffic. Investigate immediately.",
                })

    if entry_count > 50:
        findings.append({
            "category": "hosts",
            "id": "hosts-file-large",
            "severity": "medium",
            "message": f"Hosts file has an unusually large number of entries ({entry_count}) — "
                       f"review for unwanted redirects.",
        })

    return findings
