"""Cookie flag auditing."""


def check_cookies(response) -> list:
    findings = []

    for cookie in response.cookies:
        name = cookie.name
        flags_missing = []

        if not cookie.secure:
            flags_missing.append("Secure")

        httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.get_nonstandard_attr("httponly") is not None
        raw_header = str(cookie._rest) if hasattr(cookie, "_rest") else {}
        has_httponly = "HttpOnly" in raw_header or "httponly" in {k.lower() for k in raw_header}
        if not has_httponly:
            flags_missing.append("HttpOnly")

        samesite = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        if not samesite:
            flags_missing.append("SameSite")

        if flags_missing:
            findings.append({
                "category": "cookies",
                "id": f"cookie-missing-flags-{name}",
                "severity": "medium",
                "message": f"Cookie '{name}' is missing recommended flag(s): {', '.join(flags_missing)}.",
            })

    return findings
