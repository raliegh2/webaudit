"""CORS misconfiguration detection (passive — inspects response headers only)."""

import requests


def check_cors(response, url: str) -> list:
    findings = []
    headers = response.headers

    acao = headers.get("Access-Control-Allow-Origin")
    acac = headers.get("Access-Control-Allow-Credentials")

    if acao == "*" and str(acac).lower() == "true":
        findings.append({
            "category": "cors",
            "id": "cors-wildcard-with-credentials",
            "severity": "critical",
            "message": "CORS allows wildcard origin (*) together with credentials — "
                       "this combination is invalid per spec in browsers but indicates "
                       "a serious misconfiguration if seen.",
        })
    elif acao == "*":
        findings.append({
            "category": "cors",
            "id": "cors-wildcard-origin",
            "severity": "low",
            "message": "CORS Access-Control-Allow-Origin is set to '*' — "
                       "acceptable for public APIs, risky if the endpoint returns sensitive data.",
        })

    # Passive reflected-origin probe: send a benign Origin header and see if it's echoed.
    try:
        probe = requests.get(
            url, headers={"Origin": "https://webaudit-origin-test.invalid"}, timeout=8
        )
        reflected = probe.headers.get("Access-Control-Allow-Origin")
        if reflected == "https://webaudit-origin-test.invalid":
            findings.append({
                "category": "cors",
                "id": "cors-reflects-arbitrary-origin",
                "severity": "high",
                "message": "Server reflects arbitrary Origin values in "
                           "Access-Control-Allow-Origin — allows any site to make "
                           "credentialed cross-origin requests.",
            })
    except requests.exceptions.RequestException:
        pass

    return findings
