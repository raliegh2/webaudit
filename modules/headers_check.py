"""HTTP security header analysis."""

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "message": "Content-Security-Policy header is missing — increases exposure to XSS/injection attacks.",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "message": "Strict-Transport-Security (HSTS) header is missing — allows protocol downgrade attacks.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "message": "X-Frame-Options header is missing — site may be vulnerable to clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "message": "X-Content-Type-Options header is missing — MIME sniffing not disabled.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "message": "Referrer-Policy header is missing — full referrer may leak to third parties.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "message": "Permissions-Policy header is missing — browser feature access is unrestricted by default.",
    },
}


def check_security_headers(response) -> list:
    findings = []
    headers = response.headers

    for header, meta in REQUIRED_HEADERS.items():
        if header not in headers:
            findings.append({
                "category": "headers",
                "id": f"missing-header-{header.lower()}",
                "severity": meta["severity"],
                "message": meta["message"],
            })

    hsts = headers.get("Strict-Transport-Security", "")
    if hsts and "max-age" in hsts:
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0])
            if max_age < 15552000:  # 180 days
                findings.append({
                    "category": "headers",
                    "id": "weak-hsts-max-age",
                    "severity": "low",
                    "message": f"HSTS max-age is only {max_age}s — recommend at least 180 days.",
                })
        except (ValueError, IndexError):
            pass

    server = headers.get("Server")
    if server:
        findings.append({
            "category": "headers",
            "id": "server-banner-present",
            "severity": "info",
            "message": f"Server header discloses: '{server}'",
        })

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        findings.append({
            "category": "headers",
            "id": "x-powered-by-present",
            "severity": "info",
            "message": f"X-Powered-By header discloses: '{powered_by}'",
        })

    return findings
