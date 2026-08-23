"""Heuristic process scanning: suspicious paths, name-spoofing, resource outliers."""

import os
import time

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
CPU_SAMPLE_INTERVAL = 0.2  # seconds between warm-up and real cpu_percent() reads


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

    # psutil.cpu_percent()/Process.cpu_percent() returns 0.0 on its first
    # call for a given process — there's no prior sample to diff against.
    # Prime every process once, wait briefly, then take the real reading.
    procs = list(psutil.process_iter(["pid", "name", "exe", "memory_percent"]))
    for p in procs:
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(CPU_SAMPLE_INTERVAL)

    for proc in procs:
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""

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

            try:
                cpu = proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu = 0
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
