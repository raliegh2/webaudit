"""Report assembly and export in text, JSON, and HTML formats."""

import json
from datetime import datetime, timezone

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_report(results: list) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "webaudit",
        "targets_scanned": len(results),
        "results": results,
    }


def export_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def export_text(report: dict) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(f"webaudit report — generated {report['generated_at']}")
    lines.append(f"Targets scanned: {report['targets_scanned']}")
    lines.append("=" * 60)

    for result in report["results"]:
        lines.append("")
        lines.append(f"Target: {result['target']} ({result['url']})")
        lines.append(f"Score: {result['score']}/100  Grade: {result['grade']}")
        if result["errors"]:
            for err in result["errors"]:
                lines.append(f"  [ERROR] {err}")

        findings_by_sev = sorted(
            result["findings"],
            key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info")),
        )
        if not findings_by_sev:
            lines.append("  No findings.")
        for f in findings_by_sev:
            lines.append(f"  [{f['severity'].upper():8s}] {f['message']}")
        lines.append("-" * 60)

    return "\n".join(lines)


def export_html(report: dict) -> str:
    grade_colors = {"A": "#2e7d32", "B": "#558b2f", "C": "#f9a825", "D": "#ef6c00", "F": "#c62828"}
    sev_colors = {
        "critical": "#b71c1c", "high": "#e64a19", "medium": "#f9a825",
        "low": "#1565c0", "info": "#616161",
    }

    rows = []
    for result in report["results"]:
        grade_color = grade_colors.get(result["grade"], "#616161")
        findings_html = ""
        findings_by_sev = sorted(
            result["findings"],
            key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info")),
        )
        for f in findings_by_sev:
            color = sev_colors.get(f.get("severity", "info"), "#616161")
            findings_html += (
                f'<li><span style="color:{color};font-weight:bold;">'
                f'[{f["severity"].upper()}]</span> {f["message"]}</li>'
            )
        if not findings_html:
            findings_html = "<li>No findings.</li>"

        errors_html = "".join(f"<li style='color:#b71c1c'>{e}</li>" for e in result["errors"])

        rows.append(f"""
        <div class="target-card">
          <h2>{result['target']}</h2>
          <p class="url">{result['url']}</p>
          <div class="score">
            <span class="grade" style="background:{grade_color}">{result['grade']}</span>
            <span class="score-num">{result['score']}/100</span>
          </div>
          {'<ul class="errors">' + errors_html + '</ul>' if errors_html else ''}
          <ul class="findings">{findings_html}</ul>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>webaudit report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:2rem; }}
  h1 {{ font-weight:600; }}
  .meta {{ color:#9aa0a6; margin-bottom:2rem; }}
  .target-card {{ background:#1a1d24; border-radius:10px; padding:1.5rem; margin-bottom:1.5rem; }}
  .target-card h2 {{ margin:0 0 0.25rem 0; }}
  .url {{ color:#9aa0a6; margin-top:0; }}
  .score {{ display:flex; align-items:center; gap:0.75rem; margin:1rem 0; }}
  .grade {{ color:#fff; font-weight:bold; padding:0.35rem 0.9rem; border-radius:6px; font-size:1.1rem; }}
  .score-num {{ font-size:1.1rem; color:#e6e6e6; }}
  ul.findings, ul.errors {{ padding-left:1.2rem; }}
  li {{ margin-bottom:0.4rem; line-height:1.4; }}
</style>
</head>
<body>
  <h1>webaudit security report</h1>
  <p class="meta">Generated {report['generated_at']} — {report['targets_scanned']} target(s) scanned</p>
  {''.join(rows)}
</body>
</html>"""
