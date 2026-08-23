#!/usr/bin/env python3
"""
localhunt.py — Local host-based malware and anomaly hunting.

Performs:
  - Heuristic process scanning (suspicious paths, name-spoofing, resource outliers)
  - Persistence mechanism checks (Run keys / LaunchAgents / cron & systemd)
  - Hosts file tampering detection
  - Optional --deep-scan: ClamAV, YARA, and VirusTotal hash lookups

Any destructive or state-changing action (--kill, --quarantine) requires
explicit per-item confirmation. Quarantine moves files to a local, timestamped
folder rather than deleting them, so false positives can be restored.

For authorized use on systems you own or administer only.
"""

import argparse
import platform
import sys
from datetime import datetime, timezone

from modules.process_scan import scan_processes
from modules.persistence_scan import scan_persistence
from modules.hosts_scan import scan_hosts_file
from modules.actions import kill_process, quarantine_file
from modules.report import build_report, export_text, export_json, export_html


def run_deep_scan(findings: list, vt_api_key: str = None, yara_rules_dir: str = None) -> list:
    """Layer signature-based detection on top of heuristic findings."""
    deep_findings = []
    try:
        from modules.deep_scan import run_clamav, run_yara, run_virustotal
        deep_findings.extend(run_clamav())
        deep_findings.extend(run_yara(yara_rules_dir))
        if vt_api_key:
            deep_findings.extend(run_virustotal(findings, vt_api_key))
    except ImportError as e:
        print(f"[!] Deep scan module unavailable: {e}", file=sys.stderr)
    return deep_findings


def main():
    parser = argparse.ArgumentParser(
        description="Local malware and anomaly hunting (localhunt)"
    )
    parser.add_argument(
        "--deep-scan", action="store_true",
        help="Run ClamAV, YARA, and VirusTotal checks in addition to heuristics"
    )
    parser.add_argument("--vt-api-key", help="VirusTotal API key (required for VT lookups)")
    parser.add_argument("--yara-rules", help="Path to a custom YARA rules directory")
    parser.add_argument(
        "--kill", action="store_true",
        help="Interactively prompt to kill flagged processes"
    )
    parser.add_argument(
        "--quarantine", action="store_true",
        help="Interactively prompt to quarantine flagged files"
    )
    parser.add_argument(
        "--format", choices=["text", "json", "html"], default="text",
        help="Report output format (default: text)"
    )
    parser.add_argument("--output", "-o", help="Write report to this file instead of stdout")
    args = parser.parse_args()

    print(f"[*] localhunt starting on {platform.system()} {platform.release()}")

    findings = []
    findings.extend(scan_processes())
    findings.extend(scan_persistence())
    findings.extend(scan_hosts_file())

    if args.deep_scan:
        print("[*] Running deep scan (ClamAV / YARA / VirusTotal)...")
        findings.extend(run_deep_scan(findings, args.vt_api_key, args.yara_rules))

    result = {
        "target": platform.node(),
        "url": f"local://{platform.system().lower()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "errors": [],
        "score": None,
        "grade": None,
    }
    from modules.scoring import score_findings
    result["score"], result["grade"] = score_findings(findings)

    report = build_report([result])

    if args.format == "json":
        output = export_json(report)
    elif args.format == "html":
        output = export_html(report)
    else:
        output = export_text(report)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(output)
        print(f"[*] Report written to {args.output}")
    else:
        print(output)

    actionable = [f for f in findings if f.get("action_target")]
    if args.kill:
        for f in actionable:
            if f.get("action_type") == "process":
                kill_process(f)
    if args.quarantine:
        for f in actionable:
            if f.get("action_type") == "file":
                quarantine_file(f)


if __name__ == "__main__":
    main()
