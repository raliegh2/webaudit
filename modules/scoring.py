"""Weighted risk scoring for audit findings."""

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def score_findings(findings: list) -> tuple:
    """Return (score 0-100, letter grade A-F). 100 = no issues found."""
    penalty = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    score = max(0, 100 - penalty)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade
