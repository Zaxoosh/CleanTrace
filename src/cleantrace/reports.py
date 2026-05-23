from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from pathlib import Path

from cleantrace.models import Finding, Profile
from cleantrace.readiness import readiness_for
from cleantrace.scoring import exposure_score, score_band, top_actions

REPORT_SECTIONS = [
    ("Public Web Discovery", {"web_discovery"}),
    ("Phone Exposure", {"phone_exposure"}),
    ("Breach & Dark Web Intelligence", {"breach_intel", "hibp_email"}),
    ("Tor Public URL Check", {"tor_public_check"}),
    ("Manual Evidence", {"manual_evidence"}),
    ("Social Profile Findings", {"social_profiles", "social-profile"}),
    ("Data Broker Opportunities", {"data_broker", "data_brokers"}),
]


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
        "- Findings are leads for review. This is a lead, not proof.",
        "- Removal is not guaranteed. Breach intelligence is metadata-only.",
        "",
        "## Setup Status",
        "",
    ]
    for item in readiness_for(["username", "social", "web", "brokers", "intel", "github", "tor"]):
        lines.append(f"- {item.dependency.label}: {'ready' if item.ready else item.reason}")
    lines.extend(
        [
            "",
            "## Scan Coverage",
            "",
            "- Sources checked are shown through source/plugin labels and provider metadata.",
            "- Sources skipped are usually disabled, unconfigured, or manual-only.",
            "- CleanTrace does not bypass CAPTCHA, login walls, anti-bot controls, or paywalls.",
            "",
            "## Identity-Link Graph",
            "",
        ]
    )
    graph_rows = identity_link_rows(findings)
    if graph_rows:
        lines.append("| From | Link | To | Source |")
        lines.append("| --- | --- | --- | --- |")
        lines.extend(graph_rows)
    else:
        lines.append("No identity links recorded yet.")
    lines.extend(
        [
            "",
            "## Exposure Timeline",
            "",
            "| First seen | Last seen | Severity | Title |",
            "| --- | --- | --- | --- |",
        ]
    )
    for finding in sorted(findings, key=lambda item: item.last_seen, reverse=True)[:25]:
        safe_title = finding.title.replace("|", "\\|")
        lines.append(
            f"| {finding.first_seen.date()} | {finding.last_seen.date()} | "
            f"{finding.severity} | {safe_title} |"
        )
    lines.extend(
        [
            "",
            "## Highest-Risk Exposures",
            "",
        ]
    )
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
                f"- Provider: {finding.evidence.get('provider', finding.source_plugin)}",
                f"- URL: {finding.url or 'n/a'}",
                "- What matched: "
                f"{finding.evidence.get('matched_identifiers', 'redacted/local metadata')}",
                f"- Why it matters: {finding.description}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )
    if profile.risk_sensitivity == "protected-role":
        lines.extend(
            [
                "## Protected-Role Priorities",
                "",
                (
                    "Prioritise reducing links between real name, role, home location, "
                    "phone number, and personal social accounts."
                ),
                "",
            ]
        )
    for title, sources in REPORT_SECTIONS:
        section_findings = [
            finding
            for finding in findings
            if finding.source_plugin in sources or set(finding.tags) & sources
        ]
        lines.extend([f"## {title}", ""])
        if not section_findings:
            lines.append("No findings recorded for this section.")
            lines.append("")
            continue
        for finding in section_findings:
            lines.extend(render_finding_block(finding))
    review_queue = [
        finding
        for finding in findings
        if "needs_manual_review" in finding.tags or "needs-review" in finding.tags
    ]
    lines.extend(["## Manual Review Queue", ""])
    if review_queue:
        for finding in review_queue:
            lines.append(f"- {finding.id}: {finding.title} ({finding.confidence}% confidence)")
    else:
        lines.append("No manual review leads recorded.")
    lines.extend(
        [
            "",
            "## False Positive Checklist",
            "",
            "- Does the result contain an exact email, phone number, or username?",
            "- Does the page link multiple identifiers, such as name plus location?",
            "- Could the name or username belong to another person?",
            "- Has the finding been confirmed before starting a removal request?",
            "",
            "## Provider Disclosure",
            "",
            (
                "Third-party APIs only receive identifiers for modules you explicitly enable. "
                "CleanTrace does not store leaked records, passwords, hashes, tokens, "
                "or provider raw responses."
            ),
            (
                "Tor URL checks only inspect user-provided public pages. They do not crawl, "
                "follow links, download files, or interact with forms."
            ),
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
                "and does not search private systems. Treat findings as leads for manual review. "
                "Breach intelligence is metadata-only."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def identity_link_rows(findings: list[Finding]) -> list[str]:
    rows: list[str] = []
    for finding in findings:
        evidence = finding.evidence
        if evidence.get("identity_linking_risk") or "identity-link" in finding.tags:
            left = str(evidence.get("username") or evidence.get("broker") or finding.input_type)
            right = str(
                evidence.get("site")
                or evidence.get("category")
                or finding.url
                or "public source"
            )
            rows.append(
                "| "
                + " | ".join(
                    [
                        left.replace("|", "\\|"),
                        "links to",
                        right.replace("|", "\\|"),
                        finding.source_plugin,
                    ]
                )
                + " |"
            )
    return rows[:30]


def render_finding_block(finding: Finding) -> list[str]:
    evidence = finding.evidence
    return [
        f"### {finding.title}",
        "",
        f"- Source: {finding.source_plugin}",
        f"- Provider: {evidence.get('provider', finding.source_plugin)}",
        f"- Timestamp: {finding.last_seen.isoformat()}",
        f"- Confidence: {finding.confidence}%",
        f"- Severity: {finding.severity}",
        f"- What matched: {evidence.get('matched_identifiers', 'redacted/local metadata')}",
        f"- URL: {finding.url or 'n/a'}",
        f"- Why it matters: {finding.description}",
        f"- Recommended action: {finding.remediation}",
        "",
    ]


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
