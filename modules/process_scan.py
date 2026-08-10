"""Heuristic process scanning: suspicious paths, name-spoofing, resource outliers."""

import os

SUSPICIOUS_PATH_FRAGMENTS = [
    "/tmp/", "/dev/shm/", "\\AppData\\Local\\Temp\\", "\\Public\\",
    "\\Users\\Public\\", "/var/tmp/",
]

SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe",
    "lsass.exe", "services.exe", "systemd", "init", "launchd",
}

CPU_OUTLIER_THRESHOLD = 80.0
MEM_OUTLIER_THRESHOLD = 50.0


def scan_processes() -> list:
    findings = []
    try:
        import psutil
    except ImportError:
        findings.append({
            "category": "process",
            "id": "psutil-missing",
            "severity": "info",
            "message": "psutil not installed — process scanning skipped. Install with `pip install psutil`.",
        })
        return findings

    for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""

            # Suspicious execution path
            if exe and any(frag.lower() in exe.lower() for frag in SUSPICIOUS_PATH_FRAGMENTS):
                findings.append({
                    "category": "process",
                    "id": f"suspicious-path-{info['pid']}",
                    "severity": "medium",
                    "message": f"Process '{name}' (PID {info['pid']}) is running from a "
                               f"suspicious path: {exe}",
                    "action_type": "process",
                    "action_target": info["pid"],
                })

            # Name-spoofing: system-sounding name running from a non-standard path
            if name in SYSTEM_PROCESS_NAMES and exe:
                expected_dirs = ["system32", "syswow64", "/usr/", "/sbin/", "/bin/"]
                if not any(d in exe.lower() for d in expected_dirs):
                    findings.append({
                        "category": "process",
                        "id": f"name-spoofing-{info['pid']}",
                        "severity": "high",
                        "message": f"Process named '{name}' (PID {info['pid']}) is running "
                                   f"from an unexpected location, possible spoofing: {exe}",
                        "action_type": "process",
                        "action_target": info["pid"],
                    })

            cpu = info.get("cpu_percent") or 0
            mem = info.get("memory_percent") or 0
            if cpu > CPU_OUTLIER_THRESHOLD:
                findings.append({
                    "category": "process",
                    "id": f"cpu-outlier-{info['pid']}",
                    "severity": "low",
                    "message": f"Process '{name}' (PID {info['pid']}) sustained high CPU: {cpu:.1f}%",
                })
            if mem > MEM_OUTLIER_THRESHOLD:
                findings.append({
                    "category": "process",
                    "id": f"mem-outlier-{info['pid']}",
                    "severity": "low",
                    "message": f"Process '{name}' (PID {info['pid']}) high memory use: {mem:.1f}%",
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return findings
