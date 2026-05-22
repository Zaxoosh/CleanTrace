from cleantrace.ai import build_findings_context
from cleantrace.models import Finding, Profile


def test_ai_context_redacts_emails() -> None:
    profile = Profile(id=1, slug="default", consent=True)
    finding = Finding(
        profile_id=1,
        source_plugin="test",
        input_type="email",
        input_value_hash="hash",
        title="Email finding",
        description="Found alice@example.com in public context",
        confidence=90,
        severity="medium",
        remediation="Remove alice@example.com from the page.",
    )

    context = build_findings_context(profile, [finding], [])

    assert "alice@example.com" not in context
    assert "[redacted-email]" in context
