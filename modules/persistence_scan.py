"""Persistence mechanism checks: Windows Run keys, macOS LaunchAgents, Linux cron/systemd."""

import os
import platform
import glob

# Same suspicious-path signal used in process_scan.py — an autorun entry
# pointing here is a stronger signal than one pointing at Program Files.
SUSPICIOUS_PATH_FRAGMENTS = [
    "/tmp/", "/dev/shm/", "\\appdata\\local\\temp\\", "\\public\\",
    "\\users\\public\\", "/var/tmp/", "downloads",
]


def _severity_for_target(text: str) -> str:
    lowered = text.lower()
    if any(frag in lowered for frag in SUSPICIOUS_PATH_FRAGMENTS):
        return "medium"
    return "info"


def _scan_windows_run_keys() -> list:
    findings = []
    try:
        import winreg
    except ImportError:
        return findings

    run_key_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in run_key_paths:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        findings.append({
                            "category": "persistence",
                            "id": f"run-key-{name}",
                            "severity": _severity_for_target(str(value)),
                            "message": f"Autorun entry '{name}' -> {value} ({path})",
                        })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
    return findings


def _scan_macos_launch_agents() -> list:
    findings = []
    search_dirs = [
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]
    for d in search_dirs:
        for plist in glob.glob(os.path.join(d, "*.plist")):
            findings.append({
                "category": "persistence",
                "id": f"launch-agent-{os.path.basename(plist)}",
                "severity": _severity_for_target(plist),
                "message": f"LaunchAgent/Daemon present: {plist}",
            })
    return findings


def _scan_linux_cron_systemd() -> list:
    findings = []

    cron_paths = ["/etc/crontab", "/etc/cron.d"]
    for path in cron_paths:
        if os.path.isfile(path):
            findings.append({
                "category": "persistence",
                "id": f"cron-file-{path.replace('/', '_')}",
                "severity": "info",
                "message": f"Cron configuration present: {path}",
            })
        elif os.path.isdir(path):
            for entry in os.listdir(path):
                findings.append({
                    "category": "persistence",
                    "id": f"cron-entry-{entry}",
                    "severity": "info",
                    "message": f"Cron.d entry present: {path}/{entry}",
                })

    user_cron = os.path.expanduser("~/.crontab")
    if os.path.isfile(user_cron):
        findings.append({
            "category": "persistence",
            "id": "user-crontab",
            "severity": "info",
            "message": f"User crontab present: {user_cron}",
        })

    systemd_dirs = ["/etc/systemd/system", os.path.expanduser("~/.config/systemd/user")]
    for d in systemd_dirs:
        if os.path.isdir(d):
            for entry in os.listdir(d):
                if entry.endswith(".service"):
                    findings.append({
                        "category": "persistence",
                        "id": f"systemd-service-{entry}",
                        "severity": "info",
                        "message": f"systemd unit present: {os.path.join(d, entry)}",
                    })
    return findings


def scan_persistence() -> list:
    system = platform.system()
    if system == "Windows":
        return _scan_windows_run_keys()
    elif system == "Darwin":
        return _scan_macos_launch_agents()
    elif system == "Linux":
        return _scan_linux_cron_systemd()
    return []
