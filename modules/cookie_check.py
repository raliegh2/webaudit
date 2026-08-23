"""Cookie flag auditing."""


def check_cookies(response) -> list:
    findings = []

    for cookie in response.cookies:
        name = cookie.name
        flags_missing = []

        if not cookie.secure:
            flags_missing.append("Secure")

        rest = cookie._rest if hasattr(cookie, "_rest") else {}
        has_httponly = any(k.lower() == "httponly" for k in rest)
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
