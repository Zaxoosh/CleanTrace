from __future__ import annotations

import re

from cleantrace.plugins.web_discovery.models import ClassifiedWebResult, WebResult
from cleantrace.plugins.web_discovery.urltools import canonical_url
from cleantrace.security import normalise_identifier, redact


def classify_web_result(result: WebResult, identifiers: list[str]) -> ClassifiedWebResult:
    haystack = f"{result.title} {result.url} {result.snippet}".lower()
    matched = [
        item
        for item in identifiers
        if item and normalise_identifier(item) in normalise_identifier(haystack)
    ]
    classification = classify_url(result.url, haystack)
    confidence = score_confidence(matched, classification, result)
    severity = score_severity(classification, confidence, matched)
    tags = ["web_discovery", classification, result.query_set]
    if matched:
        tags.append("identifier-match")
    remediation = remediation_for(classification)
    return ClassifiedWebResult(
        result=result,
        canonical_url=canonical_url(result.url),
        matched_identifiers=[redact(item) for item in matched],
        classification=classification,
        confidence=confidence,
        severity=severity,
        tags=tags,
        remediation=remediation,
    )


def classify_url(url: str, haystack: str) -> str:
    lower_url = url.lower()
    if any(domain in lower_url for domain in ["192.com", "whitepages", "people"]):
        return "data_broker"
    if any(domain in lower_url for domain in ["github.com", "gitlab.com", "linkedin.com"]):
        return "professional_profile"
    if any(
        domain in lower_url
        for domain in ["reddit.com", "facebook.com", "instagram.com", "x.com"]
    ):
        return "social_profile"
    if any(domain in lower_url for domain in ["pastebin.com", "hastebin", "ghostbin"]):
        return "paste_or_dump_reference"
    if re.search(r"\.(pdf|docx?|xlsx?)($|\?)", lower_url):
        return "public_document"
    if any(word in haystack for word in ["forum", "thread", "comment"]):
        return "forum_post"
    if any(word in haystack for word in ["jpg", "png", "photo", "image"]):
        return "image_or_media"
    if any(word in haystack for word in ["news", "article", "press"]):
        return "news_article"
    return "needs_manual_review"


def score_confidence(matched: list[str], classification: str, result: WebResult) -> int:
    query = result.query.lower()
    if any("@" in item for item in matched):
        return 92
    if any(item.startswith("+") for item in matched):
        return 90
    if len(matched) >= 2:
        return 82
    if classification in {"professional_profile", "social_profile"} and matched:
        return 76
    if matched:
        return 62
    if classification == "paste_or_dump_reference":
        return 50
    if '"' not in query:
        return 34
    return 45


def score_severity(classification: str, confidence: int, matched: list[str]) -> str:
    if classification == "paste_or_dump_reference":
        return "high" if confidence >= 70 else "medium"
    if classification == "data_broker":
        return "high" if confidence >= 75 else "medium"
    if any("@" in item for item in matched) or any(item.startswith("+") for item in matched):
        return "high"
    if confidence >= 80:
        return "medium"
    if confidence >= 55:
        return "low"
    return "info"


def remediation_for(classification: str) -> str:
    if classification == "data_broker":
        return "Open a removal request and track the opt-out process."
    if classification == "paste_or_dump_reference":
        return "Review carefully without downloading dumps. Change reused passwords and enable MFA."
    if classification in {"professional_profile", "social_profile"}:
        return "Review profile visibility and remove unnecessary identity links."
    if classification == "public_document":
        return "Request document redaction or removal from the site owner where appropriate."
    return "Manually review the result before treating it as confirmed."
