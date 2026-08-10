# webaudit toolkit

A two-tool Python CLI security toolkit:

- **`webaudit.py`** — passive/configuration-level web application security auditing (remote).
- **`localhunt.py`** — local malware and anomaly hunting (host-based).

> ⚠️ **Authorized use only.** Only run `webaudit.py` against targets you own or
> are explicitly authorized to test. `localhunt.py` is intended for the local
> machine you're running it on.

## Install

```bash
pip install -r requirements.txt
```

`localhunt.py --deep-scan` also expects the `clamscan` binary (ClamAV) on
your PATH for antivirus signature scanning; it's skipped gracefully if not
found.

## webaudit.py — web application security auditor

Passive checks only — no exploitation, no brute force, just what a browser
would naturally see:

- HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- TLS/SSL certificate validity and protocol strength
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- CORS misconfiguration (wildcard + credentials, reflected origins)
- Information disclosure (server banners, exposed paths like `.env`, `.git/config`)

Each target gets a weighted risk score (0–100) and letter grade (A–F).

```bash
# Single target
python webaudit.py https://example.com

# Batch scan
python webaudit.py --targets-file targets.txt

# Export formats
python webaudit.py https://example.com --format json -o report.json
python webaudit.py https://example.com --format html -o report.html
```

## localhunt.py — local malware & anomaly hunter

Heuristic scanning by default:

- Suspicious process paths, name-spoofing of system processes, resource outliers
- Persistence mechanisms (Windows Run keys, macOS LaunchAgents, Linux cron/systemd)
- Hosts file tampering (e.g. blocked AV/update domains)

Optional `--deep-scan` layers in signature-based detection:

- **ClamAV** (`clamscan` binary)
- **YARA** (bundled generic rules + optional `--yara-rules <dir>`)
- **VirusTotal** hash lookups (`--vt-api-key`, free tier ~4 req/min)

```bash
# Heuristic scan only
python localhunt.py

# Full deep scan
python localhunt.py --deep-scan --vt-api-key YOUR_KEY --yara-rules ./custom_rules

# Interactive remediation (each action requires explicit confirmation)
python localhunt.py --deep-scan --kill --quarantine
```

`--kill` terminates flagged processes; `--quarantine` moves flagged files to
`~/.localhunt_quarantine` (never deletes) so false positives can be restored.

## Project structure

```
webaudit.py
localhunt.py
modules/
  headers_check.py
  tls_check.py
  cookie_check.py
  cors_check.py
  disclosure_check.py
  process_scan.py
  persistence_scan.py
  hosts_scan.py
  deep_scan.py
  actions.py
  scoring.py
  report.py
  yara_rules/
    generic.yar
requirements.txt
```
