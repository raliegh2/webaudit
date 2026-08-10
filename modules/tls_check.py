"""SSL/TLS certificate and protocol checks."""

import socket
import ssl
from datetime import datetime

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def check_tls(host: str, port: int = 443) -> list:
    findings = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                if protocol in WEAK_PROTOCOLS:
                    findings.append({
                        "category": "tls",
                        "id": "weak-tls-protocol",
                        "severity": "high",
                        "message": f"Server negotiated deprecated protocol {protocol}.",
                    })

                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "category": "tls",
                            "id": "cert-expired",
                            "severity": "critical",
                            "message": f"Certificate expired {abs(days_left)} day(s) ago.",
                        })
                    elif days_left < 30:
                        findings.append({
                            "category": "tls",
                            "id": "cert-expiring-soon",
                            "severity": "medium",
                            "message": f"Certificate expires in {days_left} day(s).",
                        })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "category": "tls",
            "id": "cert-verification-failed",
            "severity": "critical",
            "message": f"Certificate verification failed: {e}",
        })
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append({
            "category": "tls",
            "id": "tls-connection-failed",
            "severity": "info",
            "message": f"Could not establish TLS connection to check certificate: {e}",
        })

    # Attempt to detect weak protocol support by trying older contexts.
    try:
        legacy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy_context.check_hostname = False
        legacy_context.verify_mode = ssl.CERT_NONE
        legacy_context.minimum_version = ssl.TLSVersion.TLSv1
        legacy_context.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((host, port), timeout=5) as sock:
            with legacy_context.wrap_socket(sock, server_hostname=host) as ssock:
                findings.append({
                    "category": "tls",
                    "id": "legacy-protocol-accepted",
                    "severity": "high",
                    "message": f"Server accepted a legacy TLS handshake ({ssock.version()}) — should be disabled.",
                })
    except Exception:
        # Expected: server should refuse this. No finding needed on failure.
        pass

    return findings
