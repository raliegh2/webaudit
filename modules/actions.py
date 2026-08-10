"""Destructive/state-changing actions — always gated behind explicit confirmation.

Quarantine moves files rather than deleting them, so false positives can be
restored from the local quarantine folder.
"""

import os
import shutil
from datetime import datetime

QUARANTINE_DIR = os.path.expanduser("~/.localhunt_quarantine")


def kill_process(finding: dict) -> bool:
    pid = finding.get("action_target")
    message = finding.get("message", "")
    answer = input(f"\n[?] Kill process PID {pid}? ({message})\n    Type 'yes' to confirm: ")
    if answer.strip().lower() != "yes":
        print("    Skipped.")
        return False

    try:
        import psutil
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        print(f"    Process {pid} terminated.")
        return True
    except ImportError:
        print("    psutil not installed — cannot kill process.")
    except Exception as e:
        print(f"    Failed to terminate process {pid}: {e}")
    return False


def quarantine_file(finding: dict) -> bool:
    fpath = finding.get("action_target")
    message = finding.get("message", "")
    if not fpath or not os.path.isfile(fpath):
        print(f"    File not found, cannot quarantine: {fpath}")
        return False

    answer = input(f"\n[?] Quarantine file {fpath}? ({message})\n    Type 'yes' to confirm: ")
    if answer.strip().lower() != "yes":
        print("    Skipped.")
        return False

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_name = f"{timestamp}_{os.path.basename(fpath)}"
    dest_path = os.path.join(QUARANTINE_DIR, dest_name)

    try:
        shutil.move(fpath, dest_path)
        print(f"    Moved to quarantine: {dest_path}")
        return True
    except Exception as e:
        print(f"    Failed to quarantine {fpath}: {e}")
        return False
