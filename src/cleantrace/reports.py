from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from pathlib import Path

from cleantrace.models import Finding, Profile
from cleantrace.scoring import exposure_score, score_band, top_actions


def render_markdown(profile: Profile, findings: list[Finding]) -> str:
    score = exposure_score(findings, profile)
    band, _ = score_band(score)
    lines = [
        f"# CleanTrace Report: {profile.slug}",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Executive Summary",
        "",
        f"- Risk score: **{score}/100 ({band})**",
        f"- Findings reviewed: **{len(findings)}**",
        "- Scope: public exposure self-assessment using local CleanTrace data.",
        "",
        "## Highest-Risk Exposures",
        "",
    ]
    ranked = sorted(findings, key=lambda f: (f.severity, f.confidence), reverse=True)
    if not ranked:
        lines.append("No findings recorded yet.")
    for finding in ranked[:10]:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence}%",
                f"- Source: {finding.source_plugin}",
                f"- URL: {finding.url or 'n/a'}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )
    lines.extend(["## All Findings", ""])
    if findings:
        lines.append("| ID | Severity | Confidence | Source | Title | URL |")
        lines.append("| --- | --- | ---: | --- | --- | --- |")
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        finding.id,
                        finding.severity,
                        f"{finding.confidence}%",
                        finding.source_plugin,
                        finding.title.replace("|", "\\|"),
                        finding.url or "",
                    ]
                )
                + " |"
            )
    else:
        lines.append("No findings recorded yet.")
    lines.extend(["", "## Recommended Actions", ""])
    for idx, action in enumerate(top_actions(findings), start=1):
        lines.append(f"{idx}. {action}")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            (
                "CleanTrace does not guarantee complete coverage, does not delete content, "
                "and does not search private systems. Treat findings as leads for manual review."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def render_html(profile: Profile, findings: list[Finding]) -> str:
    markdown = render_markdown(profile, findings)
    body_lines = []
    in_list = False
    for line in markdown.splitlines():
        if line.startswith("# "):
            body_lines.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body_lines.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body_lines.append(f"<h3>{escape(line[4:])}</h3>")
        elif line.startswith("- ") or (len(line) > 3 and line[0].isdigit() and line[1:3] == ". "):
            if not in_list:
                body_lines.append("<ul>")
                in_list = True
            item = line[2:] if line.startswith("- ") else line[3:]
            body_lines.append(f"<li>{escape(item)}</li>")
        elif line.startswith("|"):
            continue
        elif not line.strip():
            if in_list:
                body_lines.append("</ul>")
                in_list = False
        else:
            body_lines.append(f"<p>{escape(line)}</p>")
    if in_list:
        body_lines.append("</ul>")
    score = exposure_score(findings, profile)
    band, _ = score_band(score)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CleanTrace Report - {escape(profile.slug)}</title>
  <style>
    :root {{ color-scheme: light dark; font-family: Inter, Segoe UI, sans-serif; }}
    body {{ margin: 0; background: #f7fafc; color: #111827; }}
    main {{ max-width: 960px; margin: 0 auto; padding: 40px 24px; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin-top: 32px; border-bottom: 1px solid #d1d5db; padding-bottom: 6px; }}
    h3 {{ margin-top: 24px; }}
    .score {{ display: inline-block; padding: 8px 12px; border-radius: 8px; background: #e0f2fe; }}
    li {{ margin: 6px 0; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #111827; color: #f9fafb; }}
      h2 {{ border-color: #374151; }}
      .score {{ background: #1f2937; }}
    }}
  </style>
</head>
<body>
  <main>
    <p class="score">Exposure score: {score}/100 ({escape(band)})</p>
    {''.join(body_lines)}
  </main>
</body>
</html>
"""


def write_report(profile: Profile, findings: list[Finding], fmt: str, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "markdown":
        output.write_text(render_markdown(profile, findings), encoding="utf-8")
    elif fmt == "html":
        output.write_text(render_html(profile, findings), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
    return output
