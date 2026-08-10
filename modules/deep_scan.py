"""Signature-based deep scan: ClamAV, YARA, and VirusTotal hash lookups.

These checks require external tools/services:
  - ClamAV: the `clamscan` binary must be installed and on PATH.
  - YARA: requires `pip install yara-python`. Bundles a small generic rule set
    and accepts an optional custom rules directory.
  - VirusTotal: requires a free API key (https://www.virustotal.com/) and is
    rate-limited to ~4 requests/minute on the free tier.
"""

import glob
import hashlib
import os
import shutil
import subprocess
import time

DEFAULT_SCAN_DIRS_BY_OS = {
    "Windows": [r"C:\Users", r"C:\ProgramData"],
    "Darwin": ["/tmp", os.path.expanduser("~/Downloads")],
    "Linux": ["/tmp", os.path.expanduser("~/Downloads")],
}

VT_RATE_LIMIT_SECONDS = 15  # ~4 requests/minute on free tier


def run_clamav(scan_dirs=None) -> list:
    findings = []
    clamscan_path = shutil.which("clamscan")
    if not clamscan_path:
        findings.append({
            "category": "deep-scan",
            "id": "clamav-not-installed",
            "severity": "info",
            "message": "ClamAV (`clamscan`) not found on PATH — skipping ClamAV scan.",
        })
        return findings

    import platform
    dirs = scan_dirs or DEFAULT_SCAN_DIRS_BY_OS.get(platform.system(), ["/tmp"])
    existing_dirs = [d for d in dirs if os.path.isdir(d)]

    for d in existing_dirs:
        try:
            proc = subprocess.run(
                [clamscan_path, "-r", "--infected", "--no-summary", d],
                capture_output=True, text=True, timeout=300,
            )
            for line in proc.stdout.splitlines():
                if "FOUND" in line:
                    findings.append({
                        "category": "deep-scan",
                        "id": f"clamav-hit-{hashlib.md5(line.encode()).hexdigest()[:8]}",
                        "severity": "critical",
                        "message": f"ClamAV signature match: {line.strip()}",
                        "action_type": "file",
                        "action_target": line.split(":")[0].strip(),
                    })
        except subprocess.TimeoutExpired:
            findings.append({
                "category": "deep-scan",
                "id": f"clamav-timeout-{d.replace('/', '_')}",
                "severity": "info",
                "message": f"ClamAV scan of {d} timed out.",
            })

    return findings


def run_yara(rules_dir: str = None) -> list:
    findings = []
    try:
        import yara
    except ImportError:
        findings.append({
            "category": "deep-scan",
            "id": "yara-not-installed",
            "severity": "info",
            "message": "yara-python not installed — skipping YARA scan. Install with `pip install yara-python`.",
        })
        return findings

    bundled_rules_dir = os.path.join(os.path.dirname(__file__), "yara_rules")
    rule_files = glob.glob(os.path.join(bundled_rules_dir, "*.yar"))
    if rules_dir and os.path.isdir(rules_dir):
        rule_files.extend(glob.glob(os.path.join(rules_dir, "*.yar")))

    if not rule_files:
        findings.append({
            "category": "deep-scan",
            "id": "yara-no-rules",
            "severity": "info",
            "message": "No YARA rules found (bundled or custom) — skipping YARA scan.",
        })
        return findings

    try:
        rules = yara.compile(filepaths={f"rule_{i}": f for i, f in enumerate(rule_files)})
    except yara.SyntaxError as e:
        findings.append({
            "category": "deep-scan",
            "id": "yara-compile-error",
            "severity": "info",
            "message": f"Failed to compile YARA rules: {e}",
        })
        return findings

    import platform
    scan_dirs = DEFAULT_SCAN_DIRS_BY_OS.get(platform.system(), ["/tmp"])
    for d in scan_dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    matches = rules.match(fpath, timeout=5)
                    if matches:
                        findings.append({
                            "category": "deep-scan",
                            "id": f"yara-match-{hashlib.md5(fpath.encode()).hexdigest()[:8]}",
                            "severity": "high",
                            "message": f"YARA rule(s) {[m.rule for m in matches]} matched: {fpath}",
                            "action_type": "file",
                            "action_target": fpath,
                        })
                except Exception:
                    continue

    return findings


def run_virustotal(existing_findings: list, api_key: str) -> list:
    findings = []
    try:
        import requests
    except ImportError:
        return findings

    file_paths = set()
    for f in existing_findings:
        if f.get("action_type") == "file" and f.get("action_target"):
            file_paths.add(f["action_target"])

    for fpath in file_paths:
        if not os.path.isfile(fpath):
            continue
        try:
            sha256 = hashlib.sha256()
            with open(fpath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    sha256.update(chunk)
            digest = sha256.hexdigest()

            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{digest}",
                headers={"x-apikey": api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    findings.append({
                        "category": "deep-scan",
                        "id": f"vt-hit-{digest[:8]}",
                        "severity": "critical",
                        "message": f"VirusTotal: {malicious} engine(s) flag {fpath} as malicious "
                                   f"(SHA256 {digest}).",
                    })
            elif resp.status_code == 404:
                pass  # Unknown hash — no verdict available.

            time.sleep(VT_RATE_LIMIT_SECONDS)  # respect free-tier rate limit
        except requests.exceptions.RequestException:
            continue

    return findings
