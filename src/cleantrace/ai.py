from __future__ import annotations

import json

import httpx

from cleantrace.config import AppConfig
from cleantrace.models import Finding, Profile, RemovalRequest
from cleantrace.scoring import exposure_score, top_actions
from cleantrace.security import redact_text


class AIUnavailableError(RuntimeError):
    pass


def build_findings_context(
    profile: Profile,
    findings: list[Finding],
    removals: list[RemovalRequest],
) -> str:
    payload = {
        "profile": profile.slug,
        "exposure_score": exposure_score(findings, profile),
        "top_actions": top_actions(findings),
        "findings": [
            {
                "id": finding.id,
                "source": finding.source_plugin,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "title": finding.title,
                "description": finding.description,
                "url": finding.url,
                "remediation": finding.remediation,
                "tags": finding.tags,
            }
            for finding in findings[:50]
        ],
        "removals": [
            {
                "id": removal.id,
                "status": removal.status,
                "subject": removal.subject,
                "broker": removal.broker_name,
                "finding_id": removal.finding_id,
            }
            for removal in removals[:50]
        ],
    }
    return redact_text(json.dumps(payload, indent=2, sort_keys=True))


async def ollama_generate(
    config: AppConfig,
    prompt: str,
    *,
    model: str | None = None,
) -> str:
    if config.ai_provider not in {"ollama", "none"}:
        raise AIUnavailableError("Only local Ollama is implemented in Milestone 3.")
    selected_model = model or config.ollama_model
    endpoint = config.ollama_url.rstrip("/") + "/api/generate"
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            endpoint,
            json={"model": selected_model, "prompt": prompt, "stream": False},
        )
    if response.status_code == 404:
        raise AIUnavailableError(f"Ollama model not available: {selected_model}")
    response.raise_for_status()
    data = response.json()
    return str(data.get("response") or "").strip()


def summarise_prompt(context: str) -> str:
    return f"""You are helping with a local-first privacy self-assessment.
Use only the redacted CleanTrace data below. Do not invent findings.
Provide a concise executive summary, risk themes, and practical next steps.

CleanTrace data:
{context}
"""


def actions_prompt(context: str) -> str:
    return f"""You are helping prioritize privacy cleanup actions.
Use only the redacted CleanTrace data below. Return a ranked list of concrete actions.
Prefer non-destructive actions first. Mention when manual review is required.

CleanTrace data:
{context}
"""


def removal_email_prompt(context: str, finding_id: str | None) -> str:
    target = f" for finding {finding_id}" if finding_id else ""
    return f"""Draft a concise privacy removal email{target}.
Use only the redacted CleanTrace data below. Do not include legal claims beyond a polite
privacy/removal request. Ask for confirmation and a response timeline.

CleanTrace data:
{context}
"""
